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

def offsets_from_linux_map(pid):
    lines = check_output(f"cat /proc/{pid}/maps", shell=True).splitlines()
    for l in lines:
        l = l.strip().split()
        if len(l) != 6: continue
        filename = l[5].decode('utf-8')
        if filename[0] != '/': continue
        start_addr = l[0].decode('utf-8').split("-")[0]
        yield filename, int(start_addr, 16)

# https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/python/libstdcxx/v6/printers.py#L153
class RbtreeIterator(object):
    """
    Turn an RB-tree-based container (std::map, std::set etc.) into
    a Python iterable object.
    """

    def __init__(self, rbtree):
        self._size = rbtree['_M_t']['_M_impl']['_M_node_count']
        self._node = rbtree['_M_t']['_M_impl']['_M_header']['_M_left']
        self._count = 0

    def __iter__(self):
        return self

    def __len__(self):
        return int(self._size)

    def __next__(self):
        if self._count == self._size:
            raise StopIteration
        result = self._node
        self._count = self._count + 1
        if self._count < self._size:
            # Compute the next node.
            node = self._node
            if node.dereference()['_M_right']:
                node = node.dereference()['_M_right']
                while node.dereference()['_M_left']:
                    node = node.dereference()['_M_left']
            else:
                parent = node.dereference()['_M_parent']
                while node == parent.dereference()['_M_right']:
                    node = parent
                    parent = parent.dereference()['_M_parent']
                if node.dereference()['_M_right'] != parent:
                    node = parent
            self._node = node
        return result

def get_enum_int():
    enum_type = gdb.lookup_type("junction::VMType")
    assert enum_type.code == gdb.TYPE_CODE_ENUM
    enum_values = enum_type.fields()
    for enum_val in enum_values:
        if enum_val.name == "junction::VMType::kFile":
            return int(enum_val.enumval)
    assert False, "enum for VMType::File not found"

def get_shared_ptr_ptr(shared_ptr):
    # Access the internal pointer to the managed object (_M_ptr)
    return shared_ptr['_M_ptr']

def rtti_cast(base_ptr, derived_type):
    try:
        derived_ptr = base_ptr.cast(derived_type)
        # Test if the casted pointer is valid
        gdb.execute("p *{}".format(derived_ptr), to_string=True)
        return derived_ptr
    except gdb.error:
        return None

def offsets_from_junction_map():
    map_var = gdb.parse_and_eval("'junction::detail::init_proc'.get()->mem_map_.get()->vmareas_")
    filetype = get_enum_int()
    nodetype = gdb.lookup_type("std::_Rb_tree_node<std::pair<unsigned long const, junction::VMArea> >").pointer()
    ino_type = gdb.lookup_type('junction::linuxfs::LinuxInode').pointer()
    linuxfile_type = gdb.lookup_type('junction::linuxfs::LinuxFile').pointer()

    it = RbtreeIterator(map_var)
    for node in it:
        node = node.cast(nodetype).dereference()
        valtype = node.type.template_argument(0)
        val = node['_M_storage']['_M_storage'].address.cast(valtype.pointer()).dereference()
        if int(val["second"]["type"]) != filetype:
            continue
        ptr = get_shared_ptr_ptr(val["second"]["file"])
        derived_ptr = rtti_cast(ptr, linuxfile_type)
        if not derived_ptr:
            continue
        linuxfile = derived_ptr.dereference()
        linuxinode = derived_ptr.dereference()["ino_"].cast(ino_type).dereference()
        fn = str(linuxinode["path_"])[1:-1] # strip quotes
        if fn.startswith("//"):
            fn = fn[1:]
        yield fn, val["second"]["start"]

def get_offsets(gen):
    offsets = []
    open_files_ends = dict()

    for filename, start_addr in gen:
        if filename in open_files_ends:
            if start_addr >= open_files_ends[filename]:
                del open_files_ends[filename]

        if filename not in open_files_ends:
            try:
                start, end = process_file(filename)
            except:
                continue
            real_start = start_addr - start
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

for filename, real_start in get_offsets(offsets_from_junction_map()):
   outf(f"add-symbol-file {filename} -o {hex(real_start)}")

# for filename, real_start in get_offsets(offsets_from_linux_map(pid)):
#      outf(f"add-symbol-file {filename} -o {hex(real_start)}")
