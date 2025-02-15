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

.macro SAVETF_STACK
	movq    %gs:__perthread___self(%rip), %r11
	pushq   %rax
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rax, 0
	pushq   %r15
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r15, 0
	pushq   %r14
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r14, 0
	pushq   %r13
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r13, 0
	pushq   %r12
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r12, 0
	pushq   %rbp
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rbp, 0
	pushq   %rbx
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rbx, 0
	subq    $16, %rsp
	.cfi_adjust_cfa_offset 16
	pushq   %r9
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r9, 0
	pushq   %r8
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r8, 0
	pushq   %rcx
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rcx, 0
	pushq   %rdx
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rdx, 0
	pushq   %rsi
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rsi, 0
	pushq   %rdi
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rdi, 0
	movq    %rsp, JUNCTION_TF_PTR_OFF(%r11)
.endm

.macro RESTORETF_STACK_BASE
	popq   %rdi
	.cfi_adjust_cfa_offset -8
	.cfi_restore rdi
	popq   %rsi
	.cfi_adjust_cfa_offset -8
	.cfi_restore rsi
	popq   %rdx
	.cfi_adjust_cfa_offset -8
	.cfi_restore rdx
	popq   %rcx
	.cfi_adjust_cfa_offset -8
	.cfi_restore rcx
	popq   %r8
	.cfi_adjust_cfa_offset -8
	.cfi_restore r8
	popq   %r9
	.cfi_adjust_cfa_offset -8
	.cfi_restore r9
	addq    $16, %rsp
	.cfi_adjust_cfa_offset -16
	popq   %rbx
	.cfi_adjust_cfa_offset -8
	.cfi_restore rbx
	popq   %rbp
	.cfi_adjust_cfa_offset -8
	.cfi_restore rbp
	popq   %r12
	.cfi_adjust_cfa_offset -8
	.cfi_restore r12
	popq   %r13
	.cfi_adjust_cfa_offset -8
	.cfi_restore r13
	popq   %r14
	.cfi_adjust_cfa_offset -8
	.cfi_restore r14
	popq   %r15
	.cfi_adjust_cfa_offset -8
	.cfi_restore r15
	popq   %rax
	.cfi_adjust_cfa_offset -8
	.cfi_restore rax
	// RIP into R11
	popq   %r11
	.cfi_adjust_cfa_offset -8
	.cfi_register rip, r11
	// restore rsp
	popq   %rsp
.endm

.macro RESTORETF_STACK
	RESTORETF_STACK_BASE
	.cfi_def_cfa rsp, 0
	.cfi_register rip, r11
	.cfi_val_offset rsp, 0
.endm

.macro RESTORETF_STACK_CFI_RESTORE
	RESTORETF_STACK_BASE
	.cfi_restore_state
	.cfi_def_cfa rsp, 0
	.cfi_register rip, r11
	.cfi_val_offset rsp, 0
.endm

.macro SIGCONTEXT_CFA_ONSTACK
	.cfi_def_cfa rsp, SIGFRAME_SIGCONTEXT
	.cfi_offset rsp, SIGCONTEXT_RSP
	.cfi_offset rip, SIGCONTEXT_RIP
	.cfi_offset r8, SIGCONTEXT_R8
	.cfi_offset r9, SIGCONTEXT_R9
	.cfi_offset r10, SIGCONTEXT_R10
	.cfi_offset r11, SIGCONTEXT_R11
	.cfi_offset r12, SIGCONTEXT_R12
	.cfi_offset r13, SIGCONTEXT_R13
	.cfi_offset r14, SIGCONTEXT_R14
	.cfi_offset r15, SIGCONTEXT_R15
	.cfi_offset rdi, SIGCONTEXT_RDI
	.cfi_offset rsi, SIGCONTEXT_RSI
	.cfi_offset rbp, SIGCONTEXT_RBP
	.cfi_offset rbx, SIGCONTEXT_RBX
	.cfi_offset rdx, SIGCONTEXT_RDX
	.cfi_offset rax, SIGCONTEXT_RAX
	.cfi_offset rcx, SIGCONTEXT_RCX
.endm

/*
 * CALL_SYSCALL_FUNC - macro to invoke a system call handler
 *
 * @sysnr_reg: register containing the system call number
 * @tf: register pointing to a thread_tf into which the result will be saved.
 * @return_reg: register that will contain the result of the call.
 */
.macro CALL_SYSCALL_FUNC sysnr_reg tf return_reg
	shlq    $3, \sysnr_reg
	addq    $0x200000, \sysnr_reg
	callq   *(\sysnr_reg)
	movq    %rax, RAX(\tf)
	movq    %rax, \return_reg
.endm

/*
 * usys_rt_sigreturn - target for system calls to rt_sigreturn
 *
 * the top of stack contains a pointer to the ucontext in the signal frame.
 */
.align 16
.globl usys_rt_sigreturn
.type usys_rt_sigreturn, @function
usys_rt_sigreturn:
	// disable preemption
	addl    $1, %gs:__perthread_preempt_cnt(%rip)

	// get address of runtime stack
	movq    %gs:__perthread_runtime_stack(%rip), %r11

	// use current rsp as first argument to sigreturn()
	movq    %rsp, %rdi

	// switch to runtime stack temporarily
	movq    %r11, %rsp

	jmp     usys_rt_sigreturn_finish

.globl usys_rt_sigreturn_postcall
.globl usys_rt_sigreturn_end
usys_rt_sigreturn_postcall:
usys_rt_sigreturn_end:

/**
 * __jmp_syscall_restart_nosave - restarts syscall
 * @tf: the trap frame to restore (%rdi), safe to live on the same stack as the
 * rsp that it restores to.
 *
 * Does not return.
 */
.align 16
.globl __jmp_syscall_restart_nosave
.type __jmp_syscall_restart_nosave, @function
__jmp_syscall_restart_nosave:

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
	movq    R8(%rdi), %r8 /* ARG4 */
	movq    R9(%rdi), %r9 /* ARG5 */

	/* move ip and stack to temp registers */
	movq    RIP(%rdi), %r11
	movq    RSP(%rdi), %r10

	/* restore RDI, lose access to tf */
	movq    RDI(%rdi), %rdi /* ARG0 */

	/* restore IP and stack */
	movq %r10, %rsp
	jmpq *%r11
	nop


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
 * __switch_and_interrupt_enable - switches stacks,
 * calls new function with 3 argument registers
 * @tf: the trap frame to restore (%rdi)
 *
 * Re-enables interrupts.
 * Does not return.
 */
.align 16
.globl __switch_and_interrupt_enable
.type __switch_and_interrupt_enable, @function
__switch_and_interrupt_enable:

	/* restore ip and stack */
	movq    RSP(%rdi), %rsp
	movq    RIP(%rdi), %rcx

	/* set arguments */
	movq    RSI(%rdi), %rsi /* ARG1 */
	movq    RDX(%rdi), %rdx /* ARG2 */
	movq    RDI(%rdi), %rdi /* ARG0 */

	/* enable interrupts */
	stui

	/* jump into trap frame */
	jmpq	*%rcx
	nop

/*
 * Macro that does a looped check for signals upon exit by clearing the
 * in_kernel flag and then checking for pending signals. If any signals are
 * found, it restores the in_kernel flag and calls the signal handling routine,
 * and then tries again.
 *
 * @final_unwind is assembly code to return from the system call once no signals
 * are pending.
 * @pre_run_signals and @post_run_signals are hooks that run before/after the
 * signal handler is run. Mainly used to enable/disable interrupts.
 */
.macro INTERRUPT_CHECK caller_fn final_unwind pre_run_signals post_run_signals
.globl \caller_fn\()_postcall
\caller_fn\()_postcall:
	movq    %gs:__perthread___self(%rip), %r11
	// Clear in_syscall flag and re-enable interrupts
	movb    $0, JUNCTION_IN_SYSCALL_OFF(%r11)

	// check for interrupts
	movb    JUNCTION_INT_STATE_OFF(%r11), %cl
	test    %cl, %cl
	jg      1f

	\final_unwind

1:
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)
	\pre_run_signals
	call    RunSignals
	xorq    %rdi, %rdi
	\post_run_signals
	jmp     \caller_fn\()_postcall
.globl \caller_fn\()_end
\caller_fn\()_end:
.endm

.macro RT_SIGRETURN
	jmp     syscall_rt_sigreturn
.endm

/**
 * __syscall_trap_return - returns from a trapped syscall instruction
 * This is the "restorer" function for a signal delivered by a seccomp trap.
 * When called, %rax contains the return value of the syscall and the stack
 * pointer points to the sigcontext that will be restored by the actual kernel's
 * rt_sigreturn() system call.
 *
 * No return.
 */
.align 16
.globl __syscall_trap_return
.type __syscall_trap_return, @function

__syscall_trap_return:
	.cfi_startproc simple
	.cfi_signal_frame
	SIGCONTEXT_CFA_ONSTACK

	// store rax in sigframe
	movq    %rax, SIGFRAME_RAX_OFFSET(%rsp)

	// setup return value as 1st argument for RunSignals
	movq    %rax, %rdi

	INTERRUPT_CHECK __syscall_trap_return RT_SIGRETURN
	.cfi_endproc

/**
 * __kframe_unwind_loop - similar to __syscall_trap_return, but the frame
 * restored doesn't have to be a trapped syscall. As such, it does not alter rax
 * in the frame and ensures that RunSignals gets a 0 for RAX (so there is no
 * restart system call fixup).
 *
 * No return.
 */
.align 16
.globl __kframe_unwind_loop
.type __kframe_unwind_loop, @function
__kframe_unwind_loop:
	.cfi_startproc simple
	.cfi_signal_frame
	SIGCONTEXT_CFA_ONSTACK
	xorq    %rdi, %rdi

	INTERRUPT_CHECK __kframe_unwind_loop RT_SIGRETURN
	.cfi_endproc

/**
 * __syscall_trap_return_uintr - returns from a trapped syscall instruction
 * This is the "restorer" function for a signal delivered by a seccomp trap.
 * When called, %rax contains the return value of the syscall and the stack
 * pointer points to the sigcontext that will be restored by the actual kernel's
 * rt_sigreturn() system call. This variant to be used when UINTR is enabled.
 *
 * No return.
 */

.globl __syscall_trap_return_uintr
.type __syscall_trap_return_uintr, @function

.align 16
__syscall_trap_return_uintr:
	.cfi_startproc simple
	.cfi_signal_frame
	SIGCONTEXT_CFA_ONSTACK
	// store rax in sigframe
	movq    %rax, SIGFRAME_RAX_OFFSET(%rsp)

	// align stack
	subq    $8, %rsp

	// get addr of k_sigframe for UintrKFrameLoopReturn
	movq    %rsp, %rdi

	// setup return value as 2nd argument for UintrKFrameLoopReturn
	movq    %rax, %rsi

	jmp     UintrKFrameLoopReturn
	nop
	.cfi_endproc

#define TMP_RIP %r8
#define TMP_RSP %r9
#define TMP_RFLAGS %r10


/* __kframe_unwind_uiret - immediately restore a kernel signal frame using the
 * uiret instruction to avoid a syscall. Expect %rsp to be a pointer to the
 * k_ucontext for this frame.
 */

.align 16
.globl __kframe_unwind_uiret
.type __kframe_unwind_uiret, @function
__kframe_unwind_uiret:
	.cfi_startproc simple
	.cfi_signal_frame
	SIGCONTEXT_CFA_ONSTACK

	// get rid of unneeded part of ucontext
	addq    $SIGFRAME_SIGCONTEXT, %rsp
	.cfi_adjust_cfa_offset 8

	// shuffle final fields in sigcontext to match uiret format
	movq    SIGCONTEXT_RIP(%rsp), TMP_RIP
	movq    SIGCONTEXT_RSP(%rsp), TMP_RSP
	movq    SIGCONTEXT_EFLAGS(%rsp), TMP_RFLAGS

	movq    TMP_RIP, SIGCONTEXT_RSP(%rsp)
	movq    TMP_RFLAGS, SIGCONTEXT_RIP(%rsp)
	movq    TMP_RSP, SIGCONTEXT_EFLAGS(%rsp)

	// get address of xstate
	movq    SIGCONTEXT_XSTATE(%rsp), %r11

	// set eax:edx to component mask saved in xstate
	movq    0x200(%r11),%rax
	movq    %rax,%rdx
	shrq    $0x20,%rdx

	// restore xstate
	xrstor   (%r11)

	// restore general registers
	popq    %r8
	.cfi_adjust_cfa_offset -8
	popq    %r9
	.cfi_adjust_cfa_offset -8
	popq    %r10
	.cfi_adjust_cfa_offset -8
	popq    %r11
	.cfi_adjust_cfa_offset -8
	popq    %r12
	.cfi_adjust_cfa_offset -8
	popq    %r13
	.cfi_adjust_cfa_offset -8
	popq    %r14
	.cfi_adjust_cfa_offset -8
	popq    %r15
	.cfi_adjust_cfa_offset -8
	popq    %rdi
	.cfi_adjust_cfa_offset -8
	popq    %rsi
	.cfi_adjust_cfa_offset -8
	popq    %rbp
	.cfi_adjust_cfa_offset -8
	popq    %rbx
	.cfi_adjust_cfa_offset -8
	popq    %rdx
	.cfi_adjust_cfa_offset -8
	popq    %rax
	.cfi_adjust_cfa_offset -8
	popq    %rcx
	.cfi_adjust_cfa_offset -8

	// restore rip, rsp, and rflags, and re-enable interrupts.
	uiret
	nop
	.cfi_endproc

/**
 * Macro for function call syscall entry that does not stack-switching.
 * The system call number is the first stack argument or in %rax, depending on
 * the SyscallStackArgument flag. After calling, %r11 is set to thread_self and
 * %rax holds the system call number, and a saved thread_tf is on the stack at
 * %rsp.
 */
.set SyscallStackArgument, 1
.macro JUNCTION_FNCALL_PROLOGUE
	.cfi_startproc

	// align stack
	subq $8, %rsp
	.cfi_adjust_cfa_offset 8

	// save original rax
	pushq %rax
	.cfi_adjust_cfa_offset 8
	.cfi_offset rax, -16


	.if SyscallStackArgument
		// get system call number from stack
		movq 24(%rsp), %rax
	.endif

	// push return stack pointer
	leaq  24(%rsp), %r11
	pushq %r11
	.cfi_adjust_cfa_offset 8

	// push return IP
	movq 24(%rsp), %r11
	pushq   %r11
	.cfi_adjust_cfa_offset 8

	SAVETF_STACK
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)

.endm

.macro JUNCTION_FNCALL_PROLOGUE_EAX
	.set SyscallStackArgument, 0
	JUNCTION_FNCALL_PROLOGUE
	.set SyscallStackArgument, 1
.endm

/**
 * Macro for function call syscall entry that does stack-switching.
 * The system call number is the first stack argumentor in %rax, depending on
 * the SyscallStackArgument flag. After calling, %r11 is set to thread_self and
 * %rax holds the system call number, and a saved thread_tf is on the stack at
 * %rsp.
 */
 .set SyscallStackArgument, 1
.macro JUNCTION_FNCALL_STACKSWITCH_PROLOGUE
	.cfi_startproc

	// Mark begin syscall, *before* starting to use the syscall stack.
	movq    %gs:__perthread___self(%rip), %r11;
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11);

	// Find bottom of syscall stack
	movq    JUNCTION_STACK_OFFSET(%r11), %r11;

	// subtract 16 to (A) leave space for unused fsbase field in trapframe
	// and (B) ensure correct alignment for the next call
	addq    $(JUNCTION_STACK_SIZE - JUNCTION_STACK_RESERVED - 16), %r11;

	// save return stack pointer to new stack
	leaq    8(%rsp), %r10;
	movq    %r10, -16(%r11);

	// save RIP to new stack
	movq    (%rsp), %r10;
	movq    %r10, -24(%r11);

	// save original rax
	movq    %rax, -8(%r11);

	.if SyscallStackArgument
		// get system call number from stack
		movq    8(%rsp), %rax
	.endif

	// switch to new stack
	leaq    -24(%r11), %rsp;

	// New CFI prologue
	.cfi_remember_state
	.cfi_def_cfa rsp, 24
	.cfi_offset rax, -8
	.cfi_offset rsp, -16
	.cfi_offset rip, -24

	SAVETF_STACK

.endm

.macro JUNCTION_FNCALL_STACKSWITCH_PROLOGUE_EAX
	.set SyscallStackArgument, 0
	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE
	.set SyscallStackArgument, 1
.endm

/*
 * junction_fncall_enter - main entry point for system calls.
 * This routine saves the trapframe at entry on the stack and stores a pointer
 * in the thread struct. This enables the system call to be restarted easily at
 * a later point. Before returning, checks/applies pending signals.
 *
 * NOTE: this routine expects the system call number to be passed as the first
 * stack argument.
 *
 */
.align 16
.globl junction_fncall_enter
.type junction_fncall_enter, @function
junction_fncall_enter:
	JUNCTION_FNCALL_PROLOGUE

	CALL_SYSCALL_FUNC %rax %rsp %rdi

.macro FNCALL_RET_NOSAVE
	movq    RAX(%rsp), %rax
	addq    $(19 * 8), %rsp // remove 18 registers on stack plus alignment
	.cfi_adjust_cfa_offset -152;
	ret
.endm

	INTERRUPT_CHECK junction_fncall_enter FNCALL_RET_NOSAVE

	.cfi_endproc

/*
 * junction_fncall_stackswitch_enter - entry point for runtimes that require
 * system calls to run on separate stacks.
 *
 * NOTE: this routine expects the system call number to be passed as the first
 * stack argument.
 */
.align 16
.globl junction_fncall_stackswitch_enter
.type junction_fncall_stackswitch_enter, @function
junction_fncall_stackswitch_enter:
	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE

	CALL_SYSCALL_FUNC %rax %rsp %rdi

.macro FNCALL_STACKSWITCH_NOSAVE
	// restore stack pointer
	movq    RAX(%rsp), %rax
	movq    RSP(%rsp), %rsp
	.cfi_restore_state
	.cfi_adjust_cfa_offset -8
	subq    $8, %rsp
	.cfi_adjust_cfa_offset 8
	ret
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter FNCALL_STACKSWITCH_NOSAVE

	.cfi_endproc

/*
 * junction_fncall_stackswitch_enter_uintr - entry point for runtimes that
 * require system calls to run on separate stacks. This variant must be used
 * when UINTR is enabled.
 *
 * NOTE: this routine expects the system call number to be passed as the first
 * stack argument.
 */
.align 16
.globl junction_fncall_stackswitch_enter_uintr
.type junction_fncall_stackswitch_enter_uintr, @function
junction_fncall_stackswitch_enter_uintr:

	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE

	CALL_SYSCALL_FUNC %rax %rsp %rdi

.macro FNCALL_STACKSWITCH_NOSAVE_UINTR
	// restore stack pointer
	movq    RAX(%rsp), %rax
	movq    RSP(%rsp), %rsp
	.cfi_restore_state
	.cfi_adjust_cfa_offset -8

	// enable interrupts once we are off the system call stack
	stui
	subq    $8, %rsp
	.cfi_adjust_cfa_offset 8
	ret
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_uintr FNCALL_STACKSWITCH_NOSAVE_UINTR stui clui
	.cfi_endproc


/*
 * junction_fncall_enter_preserve_regs - variant of junction_fncall_enter that
 * preserves argument registers. This is needed for vfork/clone/clone3.
 */
.align 16
.globl junction_fncall_enter_preserve_regs
.type junction_fncall_enter_preserve_regs, @function
junction_fncall_enter_preserve_regs:

	JUNCTION_FNCALL_PROLOGUE_EAX

	CALL_SYSCALL_FUNC %rax %rsp %rdi

.macro FNCALL_RET_SAVE
	RESTORETF_STACK
	// correct rsp
	subq    $8, %rsp;
	.cfi_adjust_cfa_offset 8
	ret
.endm

	INTERRUPT_CHECK junction_fncall_enter_preserve_regs FNCALL_RET_SAVE

	.cfi_endproc


.align 16
.globl __fncall_return_exit_loop
.type __fncall_return_exit_loop, @function
__fncall_return_exit_loop:
	.cfi_startproc
	xorq   %rdi, %rdi

.macro FNCALL_RET_SAVE_JMP
	RESTORETF_STACK
	jmp     *%r11
.endm

	INTERRUPT_CHECK __fncall_return_exit_loop FNCALL_RET_SAVE_JMP
	.cfi_endproc


.align 16
.globl __fncall_return_exit_loop_uintr
.type __fncall_return_exit_loop_uintr, @function
__fncall_return_exit_loop_uintr:
	.cfi_startproc

	xorq   %rdi, %rdi

	clui

.macro FNCALL_RET_SAVE_JMP_UINTR
	RESTORETF_STACK
	stui
	jmp     *%r11
.endm

	INTERRUPT_CHECK __fncall_return_exit_loop_uintr FNCALL_RET_SAVE_JMP_UINTR stui clui
	.cfi_endproc

/*
 * junction_fncall_stackswitch_enter_preserve_regs - variant of
 * junction_fncall_stackswitch_enter that preserves argument registers. This is
 * needed for vfork/clone/clone3.
 */

.align 16
.globl junction_fncall_stackswitch_enter_preserve_regs
.type junction_fncall_stackswitch_enter_preserve_regs, @function
junction_fncall_stackswitch_enter_preserve_regs:

	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE_EAX

	CALL_SYSCALL_FUNC %rax %rsp %rdi

.macro RESTORETF_RET
	RESTORETF_STACK_CFI_RESTORE
	// in case of vfork(), the stack may no longer contain the return address.
	// jump to the previously saved return address.
	jmp     *%r11
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_preserve_regs RESTORETF_RET

	.cfi_endproc


/*
 * junction_fncall_stackswitch_enter_preserve_regs_uintr - variant of
 * junction_fncall_stackswitch_enter_uintr that preserves argument registers.
 * This is needed for vfork/clone/clone3. This variant must be used when UINTR
 * is enabled.
 */
.align 16
.globl junction_fncall_stackswitch_enter_preserve_regs_uintr
.type junction_fncall_stackswitch_enter_preserve_regs_uintr, @function
junction_fncall_stackswitch_enter_preserve_regs_uintr:

	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE_EAX

	CALL_SYSCALL_FUNC %rax %rsp %rdi

	clui

.macro RESTORETF_STUI_RET
	RESTORETF_STACK_CFI_RESTORE
	stui
	// correct rsp
	subq    $8, %rsp;
	.cfi_adjust_cfa_offset 8
	ret
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_preserve_regs_uintr RESTORETF_STUI_RET stui clui

	.cfi_endproc

