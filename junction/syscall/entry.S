/*
 * entry.S - assembly routines for entering/exiting junction for clone/fork
 * syscalls
 */

#include "entry.h"
#include <asm/unistd_64.h>
#include <base/trapframe.h>

.file "entry.S"
.section        .note.GNU-stack,"",@progbits
.text

.macro SAVETF_STACK
	movq    %gs:__perthread___self(%rip), %r11

	// skip uirrv
	subq $8, %rsp
	.cfi_adjust_cfa_offset 8

	pushq 	%rax // orig_rax
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rax, 0

	pushq	$0  // xsave_area
	.cfi_adjust_cfa_offset 8

	pushq   %rax // rax
	.cfi_adjust_cfa_offset 8

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
	pushq   %r11
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r11, 0
	pushq   %r10
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset r10, 0
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
	popq   %r10
	.cfi_adjust_cfa_offset -8
	.cfi_restore r10
	popq   %r11
	.cfi_adjust_cfa_offset -8
	.cfi_restore r11
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

	// xsave_area, orig_rax, uirrv
	addq $24, %rsp
	.cfi_adjust_cfa_offset -24

	// RIP into R11
	popq   %r11
	.cfi_adjust_cfa_offset -8
	.cfi_register rip, r11

	// rflags
	popf
	.cfi_adjust_cfa_offset -8

	// restore rsp
	popq   %rsp

	// Jump into RIP
	jmpq *%r11
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
	nop

.globl usys_rt_sigreturn_postcall
.globl usys_rt_sigreturn_end
usys_rt_sigreturn_postcall:
usys_rt_sigreturn_end:

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
	.cfi_endproc
.endm

/**
 * __syscall_trap_return - returns from a trapped syscall instruction
 * This is the "restorer" function for a signal delivered by a seccomp trap.
 * When called, %rax contains the return value of the syscall and the stack
 * pointer points to the sigcontext that will be restored.
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

	jmp __kframe_unwind_loop

	.cfi_endproc

/**
 * __kframe_unwind_loop - Exits the kernel and unwinds a kernel trapframe
 * (using rt_sigreturn or uiret). If this is not a syscall frame, the caller
 * must set rdi to 0, otherwise it should set rdi to the return value of the
 * system call.

 * No return.
 */
.align 16
.globl __kframe_unwind_loop
.type __kframe_unwind_loop, @function
__kframe_unwind_loop:
	.cfi_startproc simple
	.cfi_signal_frame
	SIGCONTEXT_CFA_ONSTACK

.macro RT_SIGRETURN
	cmpb 	$0, uintr_enabled(%rip)
	jne     __kframe_unwind_uiret
	jmp     syscall_rt_sigreturn
.endm

	INTERRUPT_CHECK __kframe_unwind_loop RT_SIGRETURN


/**
 * __kframe_syscall_jmp - jumps into a syscall handler using the arguments in
 * the kframe provided on the stack. the target address is provided as the first
 * argument and the function is called on the stack above the kframe. The caller
 * should ensure that pretcode is set to an appropriate unwinder function.
 * No return.
 */
.align 16
.globl __kframe_syscall_jmp
.type __kframe_syscall_jmp, @function
__kframe_syscall_jmp:
	.cfi_startproc simple
	.cfi_signal_frame
	SIGCONTEXT_CFA_ONSTACK

	movq %rdi, %r10

	movq (8 + SIGFRAME_SIGCONTEXT + SIGCONTEXT_RDI)(%rsp), %rdi
	movq (8 + SIGFRAME_SIGCONTEXT + SIGCONTEXT_RSI)(%rsp), %rsi
	movq (8 + SIGFRAME_SIGCONTEXT + SIGCONTEXT_RDX)(%rsp), %rdx
	movq (8 + SIGFRAME_SIGCONTEXT + SIGCONTEXT_R10)(%rsp), %rcx
	movq (8 + SIGFRAME_SIGCONTEXT + SIGCONTEXT_R8)(%rsp), %r8
	movq (8 + SIGFRAME_SIGCONTEXT + SIGCONTEXT_R9)(%rsp), %r9

	jmpq *%r10
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

	// Disable interrupts before modfying the kframe, after the modifications
	// are made the system call exit sequence can no longer be restarted.
	clui

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
 * Macro for function call syscall entry that does not stack-switch.
 * The system call number is the first stack argument or in %rax, depending on
 * the SyscallStackArgument flag. After calling, %r11 is set to thread_self and
 * %rax holds the system call number, and a saved thread_tf is on the stack at
 * %rsp.
 */
.set SyscallStackArgument, 1
.macro JUNCTION_FNCALL_PROLOGUE
	.cfi_startproc

	.if SyscallStackArgument
		// get system call number from stack
		movq 8(%rsp), %rax
	.endif

	// push return stack pointer
	leaq  8(%rsp), %r11
	pushq %r11
	.cfi_adjust_cfa_offset 8

	// rflags
	pushfq
	.cfi_adjust_cfa_offset 8

	// push return IP
	movq 16(%rsp), %r11
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

	.if SyscallStackArgument
		// get system call number from stack
		movq    8(%rsp), %rax
	.endif

	// Mark begin syscall, *before* starting to use the syscall stack.
	movq    %gs:__perthread___self(%rip), %r11;
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11);

	// Find bottom of syscall stack
	movq    JUNCTION_STACK_OFFSET(%r11), %r11;

	// subtract 16 to (A) allocate the last field of the trapframe (rsp)
	// and (B) ensure correct alignment for the next call
	leaq    (JUNCTION_STACK_SIZE - JUNCTION_STACK_RESERVED - 16)(%r11), %r11;

	// save return stack pointer to new stack
	leaq    8(%rsp), %r10;
	movq    %r10, (%r11);

	// stash RIP in R10
	movq    (%rsp), %r10;

	// switch to new stack
	movq 	%r11, %rsp;

	// New CFI prologue
	.cfi_remember_state
	.cfi_def_cfa rsp, 0
	.cfi_offset rsp, 0
	.cfi_register rip, r10

	// Save rflags
	pushfq
	.cfi_adjust_cfa_offset 8

	// Save RIP
	pushq   %r10
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rip, 0

	SAVETF_STACK

.endm

.macro JUNCTION_FNCALL_STACKSWITCH_PROLOGUE_EAX
	.set SyscallStackArgument, 0
	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE
	.set SyscallStackArgument, 1
.endm


/**
 */
.macro JUNCTION_ZPOLINE_PROLOGUE xsave_routine
	.cfi_startproc

	// Mark begin syscall, *before* starting to use the syscall stack.
	movq    %gs:__perthread___self(%rip), %r11;
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11);

	// Find bottom of syscall stack
	movq    JUNCTION_STACK_OFFSET(%r11), %r11;

	// subtract 16 to (A) allocate the last field of the trapframe (%rsp)
	// and (B) ensure correct alignment for the next call
	leaq    (JUNCTION_STACK_SIZE - 2 * JUNCTION_STACK_RESERVED - 16)(%r11), %r11;

	// save return stack pointer to new stack
	leaq    8(%rsp), %rcx;
	movq    %rcx, (%r11);

	// stash RIP in RCX
	movq    (%rsp), %rcx;

	// switch to new stack
	movq 	%r11, %rsp;

	// New CFI prologue
	.cfi_remember_state
	.cfi_def_cfa rsp, 0
	.cfi_offset rsp, 0
	.cfi_register rip, rcx

	// Save rflags
	pushfq
	.cfi_adjust_cfa_offset 8

	// Save RIP
	pushq   %rcx
	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset rip, 0

	SAVETF_STACK

	// Save the fourth argument in rcx in the trapframe so we can easily find it
	// when restarting the syscall.
	movq %r10, RCX(%rsp)

	// get address of on stack xsave area
	movq    JUNCTION_STACK_OFFSET(%r11), %r11;
	addq    $(JUNCTION_STACK_SIZE - 2 * JUNCTION_STACK_RESERVED), %r11;

	// Zero the xstate header
	movq    $0, 0x200(%r11)
	movq    $0, 0x208(%r11)
	movq    $0, 0x210(%r11)
	movq    $0, 0x218(%r11)
	movq    $0, 0x220(%r11)
	movq    $0, 0x228(%r11)
	movq    $0, 0x230(%r11)
	movq    $0, 0x238(%r11)

	\xsave_routine %r11

	// save a pointer to the xsave area
	movq %r11, XSAVE_PTR(%rsp)

	// set up syscall argument registers (rax, rcx, rdx clobbered by xsave
	// routines).
	movq RDX(%rsp), %rdx
	movq RAX(%rsp), %rax
	movq %r10, %rcx

.endm

.macro TF_FULL_RET
	movq  XSAVE_PTR(%rsp), %r11
	test %r11, %r11
	jz 4f

	// set eax:edx to component mask saved in xstate
	movq    0x200(%r11),%rax
	movq    %rax,%rdx
	shrq    $0x20,%rdx

	// restore xstate
	xrstor   (%r11)
4:
	RESTORETF_STACK
.endm

.macro XSAVEC_ROUTINE reg
	// query active xstates, result in eax:edx
	movl $1, %ecx
	xgetbv

	xsavec (\reg)
.endm

.macro XSAVE_ROUTINE reg
	movl $-1, %eax
	movl $-1, %edx

	// save all xstates
	xsave (\reg)
.endm

.align 16
.globl junction_zpoline_enter
.type junction_zpoline_enter, @function
junction_zpoline_enter:

	JUNCTION_ZPOLINE_PROLOGUE XSAVEC_ROUTINE

	CALL_SYSCALL_FUNC %rax %rsp %rdi

	INTERRUPT_CHECK junction_zpoline_enter TF_FULL_RET

.align 16
.globl junction_zpoline_enter_noxsavec
.type junction_zpoline_enter_noxsavec, @function
junction_zpoline_enter_noxsavec:

        JUNCTION_ZPOLINE_PROLOGUE XSAVE_ROUTINE

        CALL_SYSCALL_FUNC %rax %rsp %rdi

        INTERRUPT_CHECK junction_zpoline_enter_noxsavec TF_FULL_RET

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
	addq    $(21 * 8), %rsp // remove 21 registers on stack
	.cfi_adjust_cfa_offset -168;
	ret
.endm

	INTERRUPT_CHECK junction_fncall_enter FNCALL_RET_NOSAVE

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

	INTERRUPT_CHECK junction_fncall_enter_preserve_regs RESTORETF_STACK


/**
 * __functionframe_syscall_jmp - jumps into a syscall handler using the
 * arguments in the thread_tf provided on the stack. the target address is
 * provided as the first argument and the function is called on the stack above
 * the tf.
 * No return.
 */
.align 16
.globl __functionframe_syscall_jmp
.type __functionframe_syscall_jmp, @function
__functionframe_syscall_jmp:

	movq %rdi, %r10

	movq RDI(%rsp), %rdi
	movq RSI(%rsp), %rsi
	movq RDX(%rsp), %rdx
	movq RCX(%rsp), %rcx
	movq R8(%rsp), %r8
	movq R9(%rsp), %r9

	callq *%r10

	// store rax in tf
	movq    %rax, RAX(%rsp)

	// setup return value as 1st argument for RunSignals
	movq    %rax, %rdi

	jmp __fncall_return_exit_loop

.align 16
.globl __fncall_return_exit_loop
.type __fncall_return_exit_loop, @function
__fncall_return_exit_loop:
	.cfi_startproc
	INTERRUPT_CHECK __fncall_return_exit_loop TF_FULL_RET

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

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_preserve_regs RESTORETF_STACK_CFI_RESTORE

/* junction_fncall_stackswitch_enter_eax - entry point for runtimes that require
* system calls to run on separate stacks.
*
* NOTE: this routine expects the system call number to be passed in eax.
*/
.align 16
.globl junction_fncall_stackswitch_enter_eax
.type junction_fncall_stackswitch_enter_eax, @function
junction_fncall_stackswitch_enter_eax:
	JUNCTION_FNCALL_STACKSWITCH_PROLOGUE_EAX

	CALL_SYSCALL_FUNC %rax %rsp %rdi

	INTERRUPT_CHECK junction_fncall_stackswitch_enter_eax FNCALL_STACKSWITCH_NOSAVE
