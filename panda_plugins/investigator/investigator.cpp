// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {
    #include "config.h"
    #include "rr_log.h"
    #include "qemu-common.h"
    #include "panda_common.h"
    #include "panda/panda_common.h"
    #include "panda_plugin.h"
    #include "panda_plugin_plugin.h"
    #include <capstone/capstone.h>
    #include "pandalog.h"
    #include "/home/yogaub/projects/panda/qemu/panda_plugins/osi/osi_types.h"
    #include "/home/yogaub/projects/panda/qemu/panda_plugins/osi/osi_ext.h"

}

#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <cstring>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

using namespace std;

csh handle;
bool init_capstone_done = false;
cs_insn *insn;
ofstream out_file;

void init_capstone(CPUState *env) {
    cs_arch arch;
    cs_mode mode;
#ifdef TARGET_I386
    arch = CS_ARCH_X86;
    mode = env->hflags & HF_LMA_MASK ? CS_MODE_64 : CS_MODE_32;
#elif defined(TARGET_ARM)
    arch = CS_ARCH_ARM;
    mode = env->thumb ? CS_MODE_THUMB : CS_MODE_ARM;
#endif

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        printf("Error initializing capstone\n");
    }
    init_capstone_done = true;
}


static int after_block_translate(CPUState *env, TranslationBlock *tb) {
    // General initialization
    size_t count;
    uint8_t mem[1024] = {};

    // Suspect instructions
    int suspects_size = 3;
    string instr_suspects [suspects_size] = {"cpuid", "icebp", "fnstcw"};
    char bug_bytes[] = {0x08, 0x7C, 0xE3, 0x04};
    char icebp_bytes[] = {0xF1};

    if (!init_capstone_done) init_capstone(env);
    panda_virtual_memory_rw(env, tb->pc, mem, tb->size, false);
    count = cs_disasm_ex(handle, mem, tb->size, tb->pc, 0, &insn);
    
    for (unsigned i = 0; i < count; i++){
        bool suspect = false;
        string cur_instr = string(insn[i].mnemonic);

        // Check the instruction mnemonic against the array of known suspect instructions
        for (int j = 0; j < suspects_size; j++) {
            if (cur_instr.find(instr_suspects[j]) != std::string::npos){
                suspect = true;
            }
        }
        // Check if the instruction size is illegal (REP repetition attack)
        if (insn[i].size > 15){
            suspect = true;
        }
	// Check instruction bytes against known bug in bitwise or	
	int comparison;
	comparison = std::memcmp(bug_bytes, insn[i].bytes, sizeof(bug_bytes));
	if (comparison == 0){
	    suspect = true;
	}
	// Check icebp opcode
	comparison = std::memcmp(icebp_bytes, insn[i].bytes, sizeof(icebp_bytes));
        if (comparison == 0){
            suspect = true;
        }


        // If suspect, output the specifics of the instruction
        if (suspect){
            OsiProc *current = get_current_process(env);
            out_file << "Current process: " << current->name << endl;
	    out_file << "PID: " << current->pid << endl;
	    out_file << "PPID: " << current->ppid << endl;
            out_file << "Instruction mnemonic: " << cur_instr << endl;
            out_file << "Instruction operands: " << insn[i].op_str << endl;
            out_file << "Instruction size: " << insn[i].size << endl;
            out_file << "Instruction bytes: ";
            for (int k = 0; k < insn[i].size; k++){
                out_file << " ";
                char str_byte [10];
                sprintf(str_byte, "%02X", insn[i].bytes[k]);
                out_file << str_byte;
            }
   	    out_file << endl << endl; 
            free_osiproc(current);
        }
    }
    return 1;
}


// Parse arguments to get output file name, and open it
int open_out_file(){
    panda_arg_list *args = panda_get_args("investigator");
    const char *file_name = panda_parse_string(args, "file", NULL);
    //struct passwd *pw = getpwuid(getuid());
    //const char *homedir = pw->pw_dir;
    char *ext = "_clues.txt";
    char *folder =  "/clues/";
    //char *output_path = (char *) malloc (strlen(homedir) + strlen(folder) + strlen(file_name) + strlen(ext) + 1);
    char *output_path = (char *) malloc (strlen(file_name) + strlen(ext) + 1);
    
    //strcpy (output_path, homedir);
    //strcat (output_path, folder);
    strcat (output_path, file_name);
    strcat (output_path, ext);

    out_file.open(output_path, std::ofstream::out);
    
    free(output_path);
    return 1;
}


bool init_plugin(void * self){
    if(!init_osi_api()) return false;    
    panda_cb pcb;
    int check = open_out_file();
    if (check != 1){
        return false;
    }

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    return true;
}


void uninit_plugin(void *self) {
    out_file.close();
}
