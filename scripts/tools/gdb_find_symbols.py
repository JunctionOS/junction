
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


lines = check_output("cat /proc/$(pgrep junc)/maps", shell=True).splitlines()

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
        start, end = process_file(filename)
        real_start = int(start_addr, 16) - start
        sys.stdout.write(f"add-symbol-file {filename} -o {hex(real_start)}\r\n")
        open_files_ends[filename] = real_start + end
