/*
 * exec.S - assembly routines for execing new programs
 */

.file "exec.S"
.section        .note.GNU-stack,"",@progbits
.text

.align 16
.globl snapshot_exec_start
.type snapshot_exec_start, @function
snapshot_exec_start:
    /* write %fs first because we need a temp register */
    /* fsbase is 0x90 into the trapframe */
    movq 0x90(%rdi), %rax
    wrfsbase %rax
    /* %rsp points at trapframe */
    movq %rdi, %rsp
    /* restore registers */
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %rbx
    popq %rbp
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    popq %rax
    addq $0x20, %rsp
    ret

.align 16
.globl junction_exec_start
.type junction_exec_start, @function
junction_exec_start:
    movq %rdi, %r11
    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %r8, %r8
    xor %r9, %r9

    jmpq    *%r11