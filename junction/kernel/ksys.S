/*
 * ksys.S - support for Linux system calls
 */

#include <asm/unistd_64.h>

.text

.globl ksys_start
ksys_start:

.align 16
.globl ksys_default
.type ksys_default, @function
ksys_default:
	movq	8(%rsp), %rax
	movq	%rcx, %r10
	syscall
	ret

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
ksys_munmap:
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
.globl ksys_open
.type ksys_open, @function
ksys_open:
	movl	$__NR_open, %eax
	syscall
	ret

.align 16
.globl ksys_close
.type ksys_close, @function
ksys_close:
	movl	$__NR_close, %eax
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
.globl ksys_newfstatat
.type ksys_newfstatat, @function
ksys_newfstatat:
	movl	$__NR_newfstatat, %eax
	movq	%rcx, %r10
	syscall
	ret

.align 16
.globl ksys_getdents
.type ksys_getdents, @function
ksys_getdents:
	movl	$__NR_getdents, %eax
	syscall
	ret

.align 16
.globl ksys_getdents64
.type ksys_getdents64, @function
ksys_getdents64:
	movl	$__NR_getdents64, %eax
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

.globl ksys_end
ksys_end:
