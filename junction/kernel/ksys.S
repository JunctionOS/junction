/*
 * ksys.S - support for Linux system calls
 */

#include <asm/unistd_64.h>

.section        .note.GNU-stack,"",@progbits
.text

.macro SYSCALL_123 name number
.align 16
.globl ksys_\name
.type ksys_\name, @function
ksys_\name:
	movl	$\number, %eax
	syscall
	ret
.endm

.macro SYSCALL_456 name number
.align 16
.globl ksys_\name
.type ksys_\name, @function
ksys_\name:
	movl	$\number, %eax
	movq	%rcx, %r10
	syscall
	ret
.endm

.globl ksys_start
ksys_start:

SYSCALL_456 mmap __NR_mmap
SYSCALL_123 munmap __NR_munmap
SYSCALL_123 mprotect __NR_mprotect
SYSCALL_123 madvise __NR_madvise
SYSCALL_456 mremap __NR_mremap

SYSCALL_456 openat __NR_openat
SYSCALL_123 close __NR_close
// SYSCALL_123 readv __NR_readv
SYSCALL_456 pread __NR_pread64

SYSCALL_456 newfstatat __NR_newfstatat
SYSCALL_123 getdents64 __NR_getdents64
SYSCALL_456 readlinkat __NR_readlinkat

SYSCALL_123 tgkill __NR_tgkill
SYSCALL_123 exit __NR_exit_group

.align 16
.globl ksys_default
.type ksys_default, @function
ksys_default:
	movq	8(%rsp), %rax
	movq	%rcx, %r10
	syscall
	ret

.globl ksys_end
ksys_end:
