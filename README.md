# panda_plugins_c1

This repository contains plugins to be used with [PANDA](https://github.com/moyix/panda) Platform for Architecture-Neutral Dynamic Analysis.

### Investigator Plugin

The plugin collects in a file all the occurrences of some instructions which may potentially be used by malwares to detect execution inside QEMU.


* cpuid
* fnstcw
* any instruction whose lenght is more than 15 bytes (like REP prefix repetitions)
* known bug in bitwise or [or %bh, 0x04 (%ebx)]
* icebp 

If any of the instructions above is identified, the plugin will output the corresponding process, pid, ppid, instruction mnemonic, operands, size and bytes, in a file with the name specified by the passed argument.

#### Use
Use the plugin during the replay of a PANDA recording with:

    /path_to_qemu/x86_64-softmmu/qemu-system-x86_64 -m 1G -replay /path_to_logs/logs/rr/[replay name] -monitor stdio -panda osi -os windows-32-7 -panda investigator:file=[replay name (output file name)]

This plugin is intended to be used together with the [Pandalog Investigator](https://github.com/ClonedOne/pandalog_investigator) application.


### String Context Plugin

This is essentially a fork of the [stringsearch] (https://github.com/moyix/panda/tree/master/qemu/panda_plugins/stringsearch).
The main difference with stringsearch is that instead of returning the position in the replay of the desired string, it outputs the context in which the string is found.
To do so, it maintains a window of 4096 bytes around the string and prints it to file.
