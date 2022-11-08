/*
 * ksys.S - support for Linux system calls
 */

#include <asm/unistd_64.h>

.text

.globl ksys_start_addr
ksys_start_addr:

.align 16
.globl ksys_mmap
.type ksys_mmap, @function
ksys_mmap:
	movl	$__NR_mmap, %eax
	movq	%rcx, %r10
	syscall
	ret

.align 16
.globl ksys_munmap
.type ksys_munmap, @function
ksys_unmap:
	movl	$__NR_munmap, %eax
	syscall
	ret

.align 16
.globl ksys_mprotect
.type ksys_mprotect, @function
ksys_mprotect:
	movl	$__NR_mprotect, %eax
	syscall
	ret

.align 16
.globl ksys_madvise
.type ksys_madvise, @function
ksys_madvise:
	movl	$__NR_madvise, %eax
	syscall
	ret

.align 16
.globl ksys_read
.type ksys_read, @function
ksys_read:
	movl	$__NR_read, %eax
	syscall
	ret

.align 16
.globl ksys_write
.type ksys_write, @function
ksys_write:
	movl	$__NR_write, %eax
	syscall
	ret

.align 16
.globl ksys_pread
.type ksys_pread, @function
ksys_pread:
	movl	$__NR_pread64, %eax
	movq	%rcx, %r10
	syscall
	ret

.align 16
.globl ksys_pwrite
.type ksys_pwrite, @function
ksys_pwrite:
	movl	$__NR_pwrite64, %eax
	movq	%rcx, %r10
	syscall
	ret

.align 16
.globl ksys_exit
.type ksys_exit, @function
ksys_exit:
	movl	$__NR_exit_group, %eax
	syscall
	# doesn't return
	hlt
	ret

.globl ksys_end_addr
ksys_end_addr:
