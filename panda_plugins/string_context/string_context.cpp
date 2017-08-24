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

#include "/home/gio/projects/panda/qemu/panda_plugins/common/prog_point.h"
#include "pandalog.h"
#include "panda_plugin_plugin.h"

#define MAX_STRINGS 100
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


size_t read_start = 0;
size_t read_pos  = 0;
size_t read_fill = 0;

size_t write_start = 0;
size_t write_pos = 0;
size_t write_fill= 0;

uint8_t write_window[MAX_WINDOW] = {0};
uint8_t read_window[MAX_WINDOW] = {0};
uint8_t tofind[MAX_STRINGS][MAX_STRLEN] = {0};

uint32_t strlens[MAX_STRINGS] = {0};
uint32_t read_iters[MAX_STRINGS] = {0};
uint32_t write_iters[MAX_STRINGS] = {0};

int num_strings = 0;

FILE *mem_report = NULL;


// helper function to unfold the circular buffer and print it to file
void output_context(bool is_read, uint8_t *window, size_t &pos) {
    char final_string[MAX_WINDOW];
    memset(final_string, '_', MAX_WINDOW);
    printf("initial state\n%s\n\n", final_string);
    int remaining = MAX_WINDOW - pos;

    // the first pos bytes of the window need to be moved to the last
    // pos bytes of the output buffer
    // if there are remaining bytes in the buffer those must
    // be copied at the beginning of the output buffer 
    memcpy(&(final_string[remaining]), window, pos);
    char temp[pos];
    memcpy(temp, window, pos);
    printf("content in 0 to pos:\n%s\n\n", temp);
    memcpy(final_string, &(window[pos]), remaining);

    if (is_read) 
        fprintf(mem_report, "Read:\n");
    else 
        fprintf(mem_report, "Write:\n");

    fprintf(mem_report, "%s\n\n", final_string);
    printf("final state\n%s\n\n", final_string);
    pos = 0;
}


int mem_callback(bool is_read, target_ulong size, void *buf, uint8_t *window, size_t &pos, size_t &start, size_t &to_fill, uint32_t *iters) {

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];

		// remove punctuation and nulls and cast to uppercase
		 switch (val) {
            case 0: case '!': case '"': case '#': case '$':
            case '%': case '&': case '\'': case '(': case ')':
            case '*': case '+': case ',': case '-': case '.':
            case '/': case ':': case ';': case '<': case '=':
            case '>': case '?': case '@': case '[': case '\\':
            case ']': case '^': case '_': case '`': case '{':
            case '|': case '}': case '~':
                continue;
        }
		if ('a' <= val && val <= 'z') val &= ~0x20;

        window[pos] = val;

        // if to_fill is non zero it must fill the right side of the window
        if (to_fill > 0) {
            to_fill--;

            if (to_fill == 0) {
                output_context(is_read, window, pos);
                memset(window, 0, MAX_WINDOW * sizeof(uint8_t));
            }

            pos = (pos + 1) % MAX_WINDOW;
            continue;
        }

        for(int str_idx = 0; str_idx < num_strings; str_idx++) {

            if (tofind[str_idx][iters[str_idx]] == val) {
                iters[str_idx]++;

				// If this was the first character of the string
				// reset the string starting position
				if (iters[str_idx] == 1) 
					start = pos;
            }
            else {
                iters[str_idx] = 0;
            }

            // if it is the last characyer of the string,
            // the string is found
            if (iters[str_idx] == strlens[str_idx]) {
                iters[str_idx] = 0;
                to_fill = (MAX_WINDOW - strlens[str_idx]) / 2;
                printf("string %d was found!\n", str_idx);
            }

        }

        pos = (pos + 1) % MAX_WINDOW;
    }

    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(true, size, buf, read_window, read_pos, read_start, read_fill, read_iters);
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(false, size, buf, write_window, write_pos, write_start, write_fill, write_iters);
}


bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin stringsearch\n");
    panda_require("callstack_instr");
    panda_arg_list *args = panda_get_args("string_context");

    const char *prefix = panda_parse_string(args, "name", "string_context");
    char stringsfile[128] = {};
    sprintf(stringsfile, "%s_search_strings.txt", prefix);

    printf ("string_context file [%s]\n", stringsfile);

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
    if (read_fill > 0) 
        output_context(true, read_window, read_pos);
    if (write_fill > 0)
        output_context(false, write_window, write_pos);
    fclose(mem_report);
}

