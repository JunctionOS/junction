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
 * usys_clone3_enter - entry to junction for clone3 function calls
 *
 * Entry point for clone3 via function call. Caller must obey typical
 * SystemV ABI conventions. Saves callee-saved registers in
 * thread_self()->junction_tf so they can be copied to the new thread. It is
 * unsafe to use thread_self()->tf because this thread may be preempted.
 */
.align 16
.globl usys_clone3_enter
.type usys_clone3_enter, @function
usys_clone3_enter:
	/* Load address of junction_tf in struct thread */
	movq %gs:__perthread___self(%rip), %r11
	addq $JUNCTION_TF_OFF, %r11

	/* save registers */
	SAVETF_CALLEE(%r11)

	/* save RIP */
	movq    (%rsp), %r10
	movq    %r10, RIP(%r11)

	jmp usys_clone3

/**
 * usys_clone_enter - entry to junction for clone function calls
 *
 * see notes for usys_clone3_enter.
 */
.align 16
.globl usys_clone_enter
.type usys_clone_enter, @function
usys_clone_enter:
	/* Load address of junction_tf in struct thread */
	movq %gs:__perthread___self(%rip), %r11
	addq $JUNCTION_TF_OFF, %r11

	/* save registers */
	SAVETF_CALLEE(%r11)

	/* save RIP */
	movq    (%rsp), %r10
	movq    %r10, RIP(%r11)

	jmp usys_clone

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
	/* clear return value */
	xorq %rax, %rax
	jmpq *%rdi

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
.global junction_syscall_full_trap
.type junction_syscall_full_trap, @function
junction_syscall_full_trap:
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

	// Maybe switch stacks
	movq    %gs:__perthread___self(%rip), %r11
	movq    JUNCTION_STACK_OFFSET(%r11), %r10 // stack
	cmpq    %rsp, %r10
	jb      1f

	addq    $JUNCTION_STACK_SIZE, %r10
	cmpq    %rsp, %r10
	jb      1f

	// switch stacks
	movq    %r10, %rsp

1:
	// allocate stack space for redzone and xsave area
	subq    $(REDZONE_SIZE + XSAVE_BYTES), %rsp
	andq    $-64, %rsp

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
 * junction_full_restore_newth - function to start a new thread that fully
 * restores all registers and extended processor state
 * @rdi: stack pointer to be restored
 * @rsp: pointer to xsave area on stack
 *
 * Start a new thread by restoring an xsave area on the stack.
 * We arrived here using __jmp_thread which has already restored callee-saved
 * regs.
 */
.align 16
.global junction_full_restore_newth
.type junction_full_restore_newth, @function
junction_full_restore_newth:
	// restore extended states
	fxrstor64  (%rsp)

	// restore stack pointer
	movq    %rdi, %rsp

	// restore caller-saved registers
	movq    %gs:__perthread___self(%rip), %r11
	addq    $JUNCTION_TF_OFF, %r11
	RESTORETF_CALLER(%r11)

	// clear return value for new thread
	xorq    %rax, %rax

	jmpq    *%rcx
