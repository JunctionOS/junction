
/*
 * vdso_inc.S - embeds the vDSO shared library in the Junction binary.
 */

.section        .note.GNU-stack,"",@progbits

.section .vdso,"ax",@progbits

.balign 4096
.globl __libvdso_start
__libvdso_start:
.incbin "libvdso.so"
