use std::arch::asm;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use anyhow::Context;

const SYS_SNAPSHOT: usize = 455;

fn path_to_buffer(p: &std::path::Path) -> anyhow::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).context("failed to convert path to CString")
}

/// Call the junction snapshot syscall
/// Returns a bool that indicates whether the process snapshotted (false) or was restored (true)
pub fn snapshot(elf: &std::path::Path, metadata: &std::path::Path) -> anyhow::Result<bool> {
    let elf_buffer = path_to_buffer(elf)?;
    let metadata_buffer = path_to_buffer(metadata)?;

    let ret: i32;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_SNAPSHOT, // syscall number
            in("rdi") elf_buffer.as_ptr(), // elf filename
            in("rsi") metadata_buffer.as_ptr(), // metadata filename
            out("rcx") _, // clobbered by syscalls
            out("r11") _, // clobbered by syscalls
            lateout("rax") ret,
        );
    }

    Ok(ret == 0)
}
