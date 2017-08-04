#define __STDC_FORMAT_MACROS

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"
#include "panda_plugin.h"
#include "rr_log.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <sstream>
using namespace std;

#include "/home/yogaub/projects/panda/qemu/panda_plugins/common/prog_point.h"
#include "pandalog.h"
#include "/home/yogaub/projects/panda/qemu/panda_plugins/callstack_instr/callstack_instr_ext.h"
#include "panda_plugin_plugin.h"

#define MAX_STRINGS 100
#define MAX_CALLERS 128
#define MAX_STRLEN 1024
#define MAX_WINDOW 4096


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
}


// Silly: since we use these as map values, they have to be
// copy constructible. Plain arrays aren't, but structs containing
// arrays are. So we make these goofy wrappers.
struct string_pos {
    uint32_t val[MAX_STRINGS];
};

struct string_context {
    size_t writing_pos;
    size_t string_start;
	size_t to_fill;	
    uint8_t window[MAX_WINDOW];
};

std::map<prog_point, string_pos> read_text_tracker;
std::map<prog_point, string_pos> write_text_tracker;
std::map<prog_point, string_context> contexts;

uint8_t tofind[MAX_STRINGS][MAX_STRLEN];
uint32_t strlens[MAX_STRINGS];

int num_strings = 0;
int n_callers = 16;

FILE *mem_report = NULL;


// helper function to unfold the circular buffer and print it to file
void output_context(string_context context) {
    char final_string[MAX_WINDOW];
    int remaining = MAX_WINDOW - context.writing_pos;

    // the first writing_pos bytes of the window need to be moved to the last
    // writing_pos bytes of the output buffer
    // if there are remaining bytes in the buffer those must
    // be copied at the beginning of the output buffer 
    memcpy(&(final_string[remaining]), context.window, context.writing_pos);
    memcpy(final_string, &(context.window[context.writing_pos]), remaining);

    fprintf(mem_report, "%s", final_string);
    context.writing_pos = 0;
}


int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                 target_ulong size, void *buf, bool is_write,
                 std::map<prog_point,string_pos> &text_tracker) {
    prog_point p = {};
    get_prog_point(env, &p);

    string_pos &sp = text_tracker[p];
    string_context context = contexts[p];
	
	if (context.to_fill > 0) {

		// compute the actual number of bytes to insert in context window
		size_t fill_size = (context.to_fill > size) ? size : context.to_fill;

		// if the fill_size is greater than available space at buffer end,
		// new bytes must be inserted at buffer head
		if (fill_size > MAX_WINDOW - context.writing_pos) {
		    size_t available = MAX_WINDOW - context.writing_pos;
			size_t remaining = fill_size - available;

			memcpy(&(context.window[context.writing_pos]), buf, available);
			context.writing_pos = 0;

			memcpy(&(context.window[context.writing_pos]), &(((uint8_t *)buf)[available]), remaining);
			context.writing_pos = remaining;
		}
		else {
			memcpy(&(context.window[context.writing_pos]), buf, fill_size);
			context.writing_pos += fill_size;
		}

		context.to_fill -= fill_size;

		// if to_fill is 0 it means the buffer is ready to be written on file
		if (context.to_fill == 0) {	
            output_context(context);
            contexts.erase(p);
   		}

        return 1;
		
	}

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        for(int str_idx = 0; str_idx < num_strings; str_idx++) {

            context.window[context.writing_pos] = val;
			
            if (tofind[str_idx][sp.val[str_idx]] == val) {
                sp.val[str_idx]++;

				// If this is the first character of the string
				// reset the string starting position
				if (sp.val[str_idx] == 0) 
					context.string_start = context.writing_pos;
            }
            else {
                sp.val[str_idx] = 0;
                contexts.erase(p);
                return 1;
            }

            // if it is the last characyer of the string,
            // the string is found
            if (sp.val[str_idx] == strlens[str_idx]) {
                sp.val[str_idx] = 0;
                int str_len = context.writing_pos - context.string_start;
                context.to_fill = (MAX_WINDOW - str_len) / 2;
                printf("string %d was found!\n", str_idx);
            }

            context.writing_pos = (context.writing_pos + 1) % MAX_WINDOW;

        }
    }

    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false, read_text_tracker);
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true, write_text_tracker);
}


bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin stringsearch\n");

    panda_require("callstack_instr");

    panda_arg_list *args = panda_get_args("stringsearch");

    const char *arg_str = panda_parse_string(args, "str", "");
    size_t arg_len = strlen(arg_str);
    if (arg_len > 0) {
        memcpy(tofind[num_strings], arg_str, arg_len);
        strlens[num_strings] = arg_len;
        num_strings++;
    }

    n_callers = panda_parse_uint64(args, "callers", 16);
    if (n_callers > MAX_CALLERS) n_callers = MAX_CALLERS;

    const char *prefix = panda_parse_string(args, "name", "stringsearch");
    char stringsfile[128] = {};
    sprintf(stringsfile, "%s_search_strings.txt", prefix);

    printf ("search strings file [%s]\n", stringsfile);

    std::ifstream search_strings(stringsfile);
    if (!search_strings) {
        printf("Couldn't open %s; no strings to search for. Exiting.\n", stringsfile);
        return false;
    }

    // Format: lines of colon-separated hex chars or quoted strings, e.g.
    // 0a:1b:2c:3d:4e
    // or "string" (no newlines)
    std::string line;
    while(std::getline(search_strings, line)) {
        std::istringstream iss(line);

        if (line[0] == '"') {
            size_t len = line.size() - 2;
            memcpy(tofind[num_strings], line.substr(1, len).c_str(), len);
            strlens[num_strings] = len;
        } else {
            std::string x;
            int i = 0;
            while (std::getline(iss, x, ':')) {
                tofind[num_strings][i++] = (uint8_t)strtoul(x.c_str(), NULL, 16);
                if (i >= MAX_STRLEN) {
                    printf("WARN: Reached max number of characters (%d) on string %d, truncating.\n", MAX_STRLEN, num_strings);
                    break;
                }
            }
            strlens[num_strings] = i;
        }

        printf("stringsearch: added string of length %d to search set\n", strlens[num_strings]);

        if(++num_strings >= MAX_STRINGS) {
            printf("WARN: maximum number of strings (%d) reached, will not load any more.\n", MAX_STRINGS);
            break;
        }
    }

    char matchfile[128] = {};
    sprintf(matchfile, "%s_string_contexts.txt", prefix);
    mem_report = fopen(matchfile, "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return false;
    }

    if(!init_callstack_instr_api()) return false;

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);


    return true;
}

void uninit_plugin(void *self) {
    map<prog_point, string_context>::iterator it;
    for ( it = contexts.begin(); it != contexts.end(); it++ ){
        string_context cur_con = it -> second;
        output_context(cur_con); 
    } 
    fclose(mem_report);
}

