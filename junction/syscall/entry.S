/*
 * entry.S - assembly routines for entering/exiting junction for clone/fork
 * syscalls
 */

#include "entry.h"

.file "entry.S"
.section        .note.GNU-stack,"",@progbits
.text

/* arguments registers (can be clobbered) */
#define RDI	(0)
#define RSI	(8)
#define RDX	(16)
#define RCX	(24)
#define R8	(32)
#define R9	(40)

/* temporary registers (can be clobbered) */
#define R10	(48)
#define R11	(56)

/* callee-saved registers (can not be clobbered) */
#define RBX	(64)
#define RBP	(72)
#define R12	(80)
#define R13	(88)
#define R14	(96)
#define R15	(104)

/* special-purpose registers */
#define RAX	(112)	/* return code */
#define RIP	(120)	/* instruction pointer */
#define RSP	(128)	/* stack pointer */
#define FSBASE	(136)	/* fsbase */

#define SAVETF_CALLEE(tf) \
	movq    %rbx, RBX(tf); \
	movq    %rbp, RBP(tf); \
	movq    %r12, R12(tf); \
	movq    %r13, R13(tf); \
	movq    %r14, R14(tf); \
	movq    %r15, R15(tf);

// Caller-saved registers (plus r10),
// must be preserved for syscall instructions
#define SAVETF_CALLER(tf) \
	movq	%rdi, RDI(tf); \
	movq    %rsi, RSI(tf); \
	movq    %rdx, RDX(tf); \
	movq    %rcx, RCX(tf); \
	movq    %r8, R8(tf);   \
	movq    %r9, R9(tf);   \
	movq    %r10, R10(tf);


#define RESTORETF_CALLER(tf) \
	movq    RDI(tf), %rdi; \
	movq    RSI(tf), %rsi; \
	movq    RDX(tf), %rdx; \
	movq    RCX(tf), %rcx; \
	movq    R8(tf), %r8;   \
	movq    R9(tf), %r9;   \
	movq    R10(tf), %r10;

/**
 * clone_fast_start - routine to start children created with clone
 * @rdi: entry address for child to run
 *
 * Entry point for a child created from a clone system call with correct rax (0)
 */
.align 16
.globl clone_fast_start
.type clone_fast_start, @function
clone_fast_start:
	movq %gs:__perthread___self(%rip), %r11
	addq $JUNCTION_TF_OFF, %r11

	RESTORETF_CALLER(%r11)

	movq RIP(%r11), %r11

	/* clear return value */
	xorq %rax, %rax

	jmpq *%r11

.align 16
.global usys_rt_sigreturn_enter
.type usys_rt_sigreturn_enter, @function
usys_rt_sigreturn_enter:
	// get address of syscall stack
	movq    %gs:__perthread___self(%rip), %r11
	movq    JUNCTION_STACK_OFFSET(%r11), %r11 // stack
	addq    $JUNCTION_STACK_SIZE, %r11

	// use current rsp as first argument to sigreturn()
	movq %rsp, %rdi

	// switch to syscall stack temporarily
	movq %r11, %rsp

	call usys_rt_sigreturn


/**
 * junction_syscall_full_trap - syscall instruction entry point
 * @rax: syscall number
 * @rcx: return IP
 * @rdi: syscall arg1
 * @rsi: syscall arg2
 * @rdx: syscall arg3
 * @r10: syscall arg4
 * @r8: syscall arg5
 * @r9: syscall arg6
 *
 * Entry to junction via a syscall instruction. Here we assume that a trap has
 * redirected the syscall to this function. The caller only expects rax, rcx,
 * and r11 to be clobbered. We save the remaining registers and extended state.
 */
.align 16
.global __junction_syscall_intercept
.type __junction_syscall_intercept, @function
__junction_syscall_intercept:
	// get trapframe address
	movq    %gs:__perthread___self(%rip), %r11
	addq    $JUNCTION_TF_OFF, %r11

	// skip saving callee regs since we expect the syscall handler to do this

	// save registers that we must restore
	SAVETF_CALLER(%r11)

	// save rsp
	movq    %rsp, RSP(%r11)

	// move arg4 to %rcx per function call convention
	movq    %r10, %rcx

	// switch stacks
	movq    %gs:__perthread___self(%rip), %r11
	movq    JUNCTION_STACK_OFFSET(%r11), %r10 // stack

	// set stack pointer to stack bottom - XSAVE_BYTES
	addq    $(JUNCTION_STACK_SIZE - XSAVE_BYTES), %r10

	// align and set stack
	andq    $-64, %r10
	movq    %r10, %rsp

	// stash a pointer to the xsave area
	movq    %rsp, JUNCTION_XSAVEPTR_OFF(%r11)

	// save extended state
	// TODO(jsf): use xsavec
	fxsave64 (%rsp)

	// call syscall handler
	shlq    $3, %rax
	addq    $0x200000, %rax
	callq   *(%rax)

	// restore extended states
	fxrstor64  (%rsp)

	// clear stashed xsave area pointer
	movq    %gs:__perthread___self(%rip), %r11
	movq    $0, JUNCTION_XSAVEPTR_OFF(%r11)

	// get trapframe address
	addq    $JUNCTION_TF_OFF, %r11

	// Restore regs that a normal caller would have saved
	RESTORETF_CALLER(%r11)

	// Restore stack and return
	movq    RSP(%r11), %rsp
	jmpq    *%rcx

/**
 * __junction_syscall_intercept_clone_ret - function to start a new thread that fully
 * restores all registers and extended processor state
 *
 * Start a new thread by restoring an xsave area on the stack.
 * We arrived here using __jmp_thread which has already restored callee-saved
 * regs.
 */
.align 16
.global __junction_syscall_intercept_clone_ret
.type __junction_syscall_intercept_clone_ret, @function
__junction_syscall_intercept_clone_ret:
	// restore extended states
	fxrstor64  (%rsp)

	// restore caller-saved registers
	movq    %gs:__perthread___self(%rip), %r11
	addq    $JUNCTION_TF_OFF, %r11
	RESTORETF_CALLER(%r11)

	// restore stack pointer
	movq    RSP(%r11), %rsp

	// clear return value for new thread
	xorq    %rax, %rax

	jmpq    *%rcx


.align 16
.global junction_fncall_stackswitch_enter
.type junction_fncall_stackswitch_enter, @function
junction_fncall_stackswitch_enter:

	// move arg4 to %rcx per function call convention
	movq    %r10, %rcx

	// get address of syscall stack
	movq    %gs:__perthread___self(%rip), %r11
	movq    JUNCTION_STACK_OFFSET(%r11), %r11 // stack
	addq    $JUNCTION_STACK_SIZE, %r11

	// push existing stack pointer to new stack
	movq 	%rsp, -8(%r11)

	// switch stacks and align
	movq    %r11, %rsp
	subq    $16, %rsp

	// call syscall handler
	shlq    $3, %rax
	addq    $0x200000, %rax
	callq   *(%rax)

	// restore stack pointer
	addq $16, %rsp
	movq -8(%rsp), %rsp

	ret


.align 16
.global junction_fncall_stackswitch_clone_enter
.type junction_fncall_stackswitch_clone_enter, @function
junction_fncall_stackswitch_clone_enter:

	// move arg4 to %rcx per function call convention
	movq    %r10, %rcx

	// get address of junction trapframe
	movq    %gs:__perthread___self(%rip), %r11

	addq    $JUNCTION_TF_OFF, %r11

	// Save registers
	SAVETF_CALLEE(%r11)
	SAVETF_CALLER(%r11)

	// save RSP + RIP
	movq    %rsp, RSP(%r11)

	movq    (%rsp), %r10
	movq    %r10, RIP(%r11)

	// get address of syscall stack and switch
	movq    %gs:__perthread___self(%rip), %r11
	movq    JUNCTION_STACK_OFFSET(%r11), %r11 // stack
	addq    $JUNCTION_STACK_SIZE, %r11
	movq    %r11, %rsp

	callq   usys_clone

	// get address of junction trapframe
	movq    %gs:__perthread___self(%rip), %r11
	addq    $JUNCTION_TF_OFF, %r11

	movq    RSP(%r11), %rsp
	movq    R10(%r11), %r10

	ret

