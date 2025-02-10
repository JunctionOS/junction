
/*
 * vdso.S - vdso assembly routines to jump to the syscall entry point.
 * In the future, these can be customized to implement these functions without
 * going through a full syscall.
 */

#include <asm/unistd_64.h>

.section        .note.GNU-stack,"",@progbits
.text

.macro VDSO name number
.align 16
.globl __vdso_\name
.type __vdso_\name, @function
__vdso_\name:
	.cfi_startproc
	pushq $\number
	.cfi_adjust_cfa_offset 8;
	callq *0x200e28
	popq %rcx
	.cfi_adjust_cfa_offset -8;
	ret
	.cfi_endproc

.globl \name
.set \name, __vdso_\name

.endm

VDSO clock_gettime __NR_clock_gettime
VDSO getcpu __NR_getcpu
VDSO clock_getres __NR_clock_getres
VDSO gettimeofday __NR_gettimeofday
VDSO time __NR_time
