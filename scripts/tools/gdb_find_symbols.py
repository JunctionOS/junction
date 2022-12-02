#!/usr/bin/env python3

"""

Finds mmaped ELF objects and adds them to gdb at the correct offset

Usage:
GDB cli: source <path_to_this_file>
Shell: python3 <path_to_this_file>

"""


from subprocess import check_output
import sys

from elftools.elf.elffile import ELFFile

def align_down(va):
    return va - (va % 4096)

def process_file(filename):
    lowest_va = 2**64
    highest_va = 0
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_segments():
            hdr = section.header
            if hdr['p_type'] != "PT_LOAD": continue
            lowest_va = min(lowest_va, hdr['p_vaddr'])
            maxaddr = hdr['p_vaddr'] + hdr['p_memsz']
            highest_va = max(highest_va, maxaddr)
    return align_down(lowest_va), highest_va


def get_offsets(pid):
    lines = check_output(f"cat /proc/{pid}/maps", shell=True).splitlines()

    offsets = []
    open_files_ends = dict()

    for l in lines:
        l = l.strip().split()
        if len(l) != 6: continue
        filename = l[5].decode('utf-8')
        if filename[0] != '/': continue
        start_addr = l[0].decode('utf-8').split("-")[0]

        if filename in open_files_ends:
            if int(start_addr, 16) >= open_files_ends[filename]:
                del open_files_ends[filename]

        if filename not in open_files_ends:
            try:
                start, end = process_file(filename)
            except:
                continue
            real_start = int(start_addr, 16) - start
            offsets.append((filename, real_start))
            open_files_ends[filename] = real_start + end
    return offsets


outf = print
pid = None

try:
    import gdb
    outf = gdb.execute
    pid = gdb.selected_inferior().pid
except:
    pass

if not pid:
    try:
        pids = check_output("pidof junction_run", shell=True).splitlines()
        assert len(pids) == 1, "Multiple junction processes are running"
        pid = int(pids[0])
    except Exception as e:
        print(f"Couldn't identify junction process using `pgrep junction`")
        print(e)
        exit(-1)

for filename, real_start in get_offsets(pid):
    outf(f"add-symbol-file {filename} -o {hex(real_start)}")