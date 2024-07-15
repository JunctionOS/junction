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

#define RESTORETF_CALLER(tf) \
	movq    RDI(tf), %rdi; \
	movq    RSI(tf), %rsi; \
	movq    RDX(tf), %rdx; \
	movq    RCX(tf), %rcx; \
	movq    R8(tf), %r8;   \
	movq    R9(tf), %r9;   \
	movq    R10(tf), %r10;

#define SAVETF_STACK \
	movq    %gs:__perthread___self(%rip), %r11; \
	pushq   %rax; \
	pushq   %r15; \
	pushq   %r14; \
	pushq   %r13; \
	pushq   %r12; \
	pushq   %rbp; \
	pushq   %rbx; \
	subq    $16, %rsp; \
	pushq   %r9; \
	pushq   %r8; \
	pushq   %rcx; \
	pushq   %rdx; \
	pushq   %rsi; \
	pushq   %rdi; \
	movq    %rsp, JUNCTION_TF_PTR_OFF(%r11);

.macro RESTORETF_STACK
	popq   %rdi
	popq   %rsi
	popq   %rdx
	popq   %rcx
	popq   %r8
	popq   %r9
	addq    $16, %rsp
	popq   %rbx
	popq   %rbp
	popq   %r12
	popq   %r13
	popq   %r14
	popq   %r15
	popq   %rax
	// RIP into R11
	popq   %r11
	// restore rsp
	popq   %rsp
.endm


/*
 * CALL_SYSCALL_FUNC - macro to invoke a system call handler
 *
 * @sysner_reg: register containing the system call number
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
 * usys_rt_sigreturn_enter - target for system calls to rt_sigreturn
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
	// store rax in sigframe
	movq    %rax, SIGFRAME_RAX_OFFSET(%rsp)

	// setup return value as 1st argument for RunSignals
	movq    %rax, %rdi

	INTERRUPT_CHECK __syscall_trap_return RT_SIGRETURN

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
	xorq    %rdi, %rdi

	INTERRUPT_CHECK __kframe_unwind_loop RT_SIGRETURN


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

	// get rid of unneeded part of ucontext
	addq    $SIGFRAME_SIGCONTEXT, %rsp

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
	popq    %r9
	popq    %r10
	popq    %r11
	popq    %r12
	popq    %r13
	popq    %r14
	popq    %r15
	popq    %rdi
	popq    %rsi
	popq    %rbp
	popq    %rbx
	popq    %rdx
	popq    %rax
	popq    %rcx

	// restore rip, rsp, and rflags, and re-enable interrupts.
	uiret
	nop

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

	// save original rax
	pushq %rax

	.if SyscallStackArgument
		// get system call number from stack
		movq 24(%rsp), %rax
	.endif

	// push return stack pointer
	leaq  24(%rsp), %r11
	pushq %r11

	// push return IP
	movq 24(%rsp), %r11
	pushq   %r11

	SAVETF_STACK
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)

	.cfi_adjust_cfa_offset 152;
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
	subq    $8, %rsp
	ret
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter FNCALL_STACKSWITCH_NOSAVE

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

	// enable interrupts once we are off the system call stack
	stui
	subq    $8, %rsp
	ret
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_uintr FNCALL_STACKSWITCH_NOSAVE_UINTR stui clui


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
	ret
.endm

	INTERRUPT_CHECK junction_fncall_enter_preserve_regs FNCALL_RET_SAVE

	.cfi_endproc


.align 16
.globl __fncall_return_exit_loop
.type __fncall_return_exit_loop, @function
__fncall_return_exit_loop:
	xorq   %rdi, %rdi

.macro FNCALL_RET_SAVE_JMP
	RESTORETF_STACK
	jmp     *%r11
.endm

	INTERRUPT_CHECK __fncall_return_exit_loop FNCALL_RET_SAVE_JMP


.align 16
.globl __fncall_return_exit_loop_uintr
.type __fncall_return_exit_loop_uintr, @function
__fncall_return_exit_loop_uintr:

	xorq   %rdi, %rdi

	clui

.macro FNCALL_RET_SAVE_JMP_UINTR
	RESTORETF_STACK
	stui
	jmp     *%r11
.endm

	INTERRUPT_CHECK __fncall_return_exit_loop_uintr FNCALL_RET_SAVE_JMP_UINTR stui clui

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
	RESTORETF_STACK
	// in case of vfork(), the stack may no longer contain the return address.
	// jump to the previously saved return address.
	jmp     *%r11
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_preserve_regs RESTORETF_RET

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
	RESTORETF_STACK
	stui
	// correct rsp
	subq    $8, %rsp;
	ret
.endm

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_preserve_regs_uintr RESTORETF_STUI_RET stui clui
