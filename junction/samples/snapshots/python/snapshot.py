import ctypes
import mmap

def snapshot(metadata_path, elf_path):
    global snapshot
    
    buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC, flags=mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE)


    buf.write(
        b"\x48\xc7\xc0\xc7\x01\x00\x00" # mov $0x1c7, %rax
        b"\x0f\x05" # syscall
        b"\xc3" # ret
    )
    
    ftype = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    fpointer = ctypes.c_void_p.from_buffer(buf)

    b_md_path = metadata_path.encode('utf-8')
    b_elf_path = elf_path.encode('utf-8')

    snapshot = ftype(ctypes.addressof(fpointer))
    snapshot.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    
    return snapshot(ctypes.c_char_p(b_md_path), ctypes.c_char_p(b_elf_path)) == 0

if __name__ == "__main__":
    if(snapshot("/tmp/python.elf", "/tmp/python.metadata")):
        print("Snapshotted!")
    else:
        print("Restored!")


