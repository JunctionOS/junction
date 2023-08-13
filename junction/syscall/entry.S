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
	movq    %gs:__perthread___self(%rip), %r11
	addq    $JUNCTION_TF_OFF, %r11

	RESTORETF_CALLER(%r11)

	movq    RIP(%r11), %r11

	/* clear return value */
	xorq    %rax, %rax

	jmpq    *%r11

/*
 * usys_rt_sigreturn_enter - target for system calls to rt_sigreturn
 *
 * the top of stack contains a pointer to the ucontext in the signal frame.
 */
.align 16
.global usys_rt_sigreturn_enter
.type usys_rt_sigreturn_enter, @function
usys_rt_sigreturn_enter:
	// disable preemption
	addl	$1, %gs:__perthread_preempt_cnt(%rip)

	// get address of runtime stack
	movq    %gs:__perthread_runtime_stack(%rip), %r11

	// use current rsp as first argument to sigreturn()
	movq    %rsp, %rdi

	// switch to syscall stack temporarily
	movq    %r11, %rsp

	jmp     usys_rt_sigreturn

/**
 * __restore_tf_full_and_preempt_enable - switches stacks,
 * restoring callee saved registers, and syscall argument registers, and RAX
 * @tf: the trap frame to restore (%rdi)
 *
 * Re-enables preemption.
 * Does not return.
 */
.align 16
.globl __restore_tf_full_and_preempt_enable
.type __restore_tf_full_and_preempt_enable, @function
__restore_tf_full_and_preempt_enable:

	/* restore ip and stack */
	movq    RSP(%rdi), %rsp
	movq    RIP(%rdi), %r11

	/* restore callee regs */
	movq    RBX(%rdi), %rbx
	movq    RBP(%rdi), %rbp
	movq    R12(%rdi), %r12
	movq    R13(%rdi), %r13
	movq    R14(%rdi), %r14
	movq    R15(%rdi), %r15
	movq    RAX(%rdi), %rax

	/* set function arguments */
	movq    RSI(%rdi), %rsi /* ARG1 */
	movq    RDX(%rdi), %rdx /* ARG2 */

	movq    RCX(%rdi), %rcx /* ARG3 */
	movq    R10(%rdi), %r10 /* ARG3 (syscall) */
	movq    R8(%rdi), %r8 /* ARG4 */
	movq    R9(%rdi), %r9 /* ARG5 */

	movq    RDI(%rdi), %rdi /* ARG0 */

	/* re-enable preemption */
	subl	$1, %gs:__perthread_preempt_cnt(%rip)
	jz	    1f

	/* jump into trap frame */
	jmpq	*%r11
	nop

1:	/* cold-path, save RIP and park the kthread */
	pushq   %r11
	pushq   %rax
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq   %r10
	pushq   %r8
	pushq   %r9
	pushq	%rcx
	pushq	%r15
	movq	%rsp, %r15
	andq	$-16, %rsp /* ensure correct stack alignment */
	call	preempt
	movq	%r15, %rsp /* restore SP */
	popq	%r15
	popq    %rcx
	popq    %r9
	popq    %r8
	popq    %r10
	popq	%rdx
	popq	%rsi
	popq	%rdi
	popq    %rax
	popq    %r11
	jmpq	*%r11

/**
 * __switch_and_preempt_enable - switches stacks,
 * calls new function with 3 argument registers
 * @tf: the trap frame to restore (%rdi)
 *
 * Re-enables preemption.
 * Does not return.
 */
.align 16
.globl __switch_and_preempt_enable
.type __switch_and_preempt_enable, @function
__switch_and_preempt_enable:

	/* restore ip and stack */
	movq    RSP(%rdi), %rsp
	movq    RIP(%rdi), %rcx

	/* set arguments */
	movq    RSI(%rdi), %rsi /* ARG1 */
	movq    RDX(%rdi), %rdx /* ARG2 */
	movq    RDI(%rdi), %rdi /* ARG0 */

	/* re-enable preemption */
	subl	$1, %gs:__perthread_preempt_cnt(%rip)
	jz	    1f

	/* jump into trap frame */
	jmpq	*%rcx
	nop

1:	/* cold-path, save RIP and park the kthread */
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%r15
	movq	%rsp, %r15
	andq	$-16, %rsp /* ensure correct stack alignment */
	call	preempt
	movq	%r15, %rsp /* restore SP */
	popq	%r15
	popq    %rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	jmpq	*%rcx

/**
 * __save_tf_switch - saves the current trap frame and jumps to a function
 * @tf: the struct thread_tf to save state (%rdi)
 * @fn: the function pointer to call (%rsi)
 * @stack: the start of the runtime stack (%rdx)
 * @arg0: an argument to pass to @fn (%rcx)
 *
 */

.align 16
.globl __save_tf_switch
.type __save_tf_switch, @function
__save_tf_switch:
	/* save callee regs */
	movq    %rbx, RBX(%rdi)
	movq    %rbp, RBP(%rdi)
	movq    %r12, R12(%rdi)
	movq    %r13, R13(%rdi)
	movq    %r14, R14(%rdi)
	movq    %r15, R15(%rdi)

	/* save ip and stack */
	movq    (%rsp), %r8
	movq    %r8, RIP(%rdi)
	leaq    8(%rsp), %r8
	movq    %r8, RSP(%rdi)

	/* setup arg0 */
	movq    %rcx, %rdi

	/* jump into runtime function */
	movq    %rdx, %rsp

	/* jump into runtime code */
	jmpq    *%rsi

/**
 * __nosave_switch - jumps to a function iwithout saving the current stack
 * frame
 * @fn: the function pointer to call (%rdi)
 * @stack: the start of the runtime stack (%rsi)
 * @arg0: an arg for @fn (%rdx)
 *
 * No return value.
 */
.align 16
.globl __nosave_switch
.type __nosave_switch, @function
__nosave_switch:

	/* jump into runtime function */
	movq    %rsi, %rsp
	movq	%rdi, %rsi

	/* setup arg0 */
	movq    %rdx, %rdi

	/* jump into runtime code */
	jmpq    *%rsi


.align 16
.global junction_fncall_stackswitch_enter
.type junction_fncall_stackswitch_enter, @function
junction_fncall_stackswitch_enter:

	// move arg4 to %rcx per function call convention
	movq    %r10, %rcx

	// check if this thread currently has an altstack setup
	movq    %gs:__perthread___self(%rip), %r11

	// save some registers into a trapframe so we can potentially
	// restart this syscall if a signal is delivered
	movq    %rbx, (JUNCTION_TF_OFF + RBX)(%r11)
	movq    %rbp, (JUNCTION_TF_OFF + RBP)(%r11)
	movq    %r12, (JUNCTION_TF_OFF + R12)(%r11)
	movq    %r13, (JUNCTION_TF_OFF + R13)(%r11)
	movq    %r14, (JUNCTION_TF_OFF + R14)(%r11)
	movq    %r15, (JUNCTION_TF_OFF + R15)(%r11)
	movq    %rax, (JUNCTION_TF_OFF + RAX)(%r11)

	movq    %rdi, (JUNCTION_TF_OFF + RDI)(%r11)
	movq    %rsi, (JUNCTION_TF_OFF + RSI)(%r11)
	movq    %rdx, (JUNCTION_TF_OFF + RDX)(%r11)
	movq    %r10, (JUNCTION_TF_OFF + R10)(%r11)
	movq    %r8,  (JUNCTION_TF_OFF +  R8)(%r11)
	movq    %r9,  (JUNCTION_TF_OFF +  R9)(%r11)

	// save ip and stack
	movq    (%rsp), %r10
	movq    %r10, (JUNCTION_TF_OFF + RIP)(%r11)
	leaq    8(%rsp), %r10
	movq    %r10, (JUNCTION_TF_OFF + RSP)(%r11)

	// calculate address of new stack
	movq    JUNCTION_STACK_OFFSET(%r11), %r11
	addq    $JUNCTION_STACK_SIZE, %r11

	// push existing stack pointer to new stack
	movq 	%rsp, -8(%r11)

	// switch stacks and align
	movq    %r11, %rsp
	subq    $16, %rsp

	// compute syscall handler address in %rax
	shlq    $3, %rax
	addq    $0x200000, %rax

	// call syscall handler
	callq   *(%rax)

	// restore stack pointer
	addq    $16, %rsp
	movq    -8(%rsp), %rsp

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

	movq    (%rsp), %r10
	movq    %r10, RIP(%r11)

	// save RSP + RIP
	movq    %rsp, RSP(%r11)

	// get address of syscall stack and switch
	movq    %gs:__perthread___self(%rip), %r11
	movq    JUNCTION_STACK_OFFSET(%r11), %r11 // stack
	addq    $JUNCTION_STACK_SIZE, %r11
	movq    %r11, %rsp

	andq    $-16, %rsp
	callq   usys_clone

	// get address of junction trapframe
	movq    %gs:__perthread___self(%rip), %r11
	addq    $JUNCTION_TF_OFF, %r11

	movq    RSP(%r11), %rsp

	ret

