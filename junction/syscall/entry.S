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

/**
 * clone_fast_start - routine to start children created with clone
 *
 */
.align 16
.globl clone_fast_start
.type clone_fast_start, @function
clone_fast_start:

	// find the trapframe
	movq 	%gs:__perthread___self(%rip), %r11
	addq    $CALADAN_TF_OFF, %r11

	RESTORETF_CALLER(%r11)

	// Get RIP for function start
	movq    R11(%r11), %r11

	/* clear return value */
	xorq    %rax, %rax

	jmpq    *%r11

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
	addl	$1, %gs:__perthread_preempt_cnt(%rip)

	// get address of runtime stack
	movq    %gs:__perthread_runtime_stack(%rip), %r11

	// use current rsp as first argument to sigreturn()
	movq    %rsp, %rdi

	// switch to syscall stack temporarily
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
 * __nosave_switch - jumps to a function without saving the current stack
 * frame
 * @fn: the function pointer to call (%rdi)
 * @stack: the start of the runtime stack (%rsi)
 * @arg0: an arg for @fn (%rdx)
 *
 * No return.
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



/**
 * __syscall_trap_return - returns from a trapped syscall instruction
 * This is the "restorer" function for a signal delivered by a seccomp trap.
 * When called, %rax contains the return value of the syscall and the stack
 * pointer points to the sigcontext that will be restored by the actual kernel's
 * rt_sigreturn() system call.
 *
 * No return.
 */

.globl __syscall_trap_return
.type __syscall_trap_return, @function
.globl __syscall_trap_exit_loop

.align 16
__syscall_trap_return:

    // store rax in sigframe
    movq    %rax, SIGFRAME_RAX_OFFSET(%rsp)

__syscall_trap_exit_loop:
    // clear syscall flag
    movq    %gs:__perthread___self(%rip), %r11
    movb    $0, JUNCTION_IN_SYSCALL_OFF(%r11)

    movl    JUNCTION_INT_STATE_OFF(%r11), %edi
    test    %edi, %edi
    jg 1f

    jmp     syscall_rt_sigreturn

1:
    movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)
    movq    SIGFRAME_RAX_OFFSET(%rsp), %rdi
    call    RunSignals
    jmp     __syscall_trap_exit_loop

#define SAVETF_STACK \
	movq 	%gs:__perthread___self(%rip), %r11; \
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

#define SAVETF_STACK_AND_MARK_SYSCALL \
	SAVETF_STACK; \
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)

#define RESTORETF_STACK \
	popq   %rdi; \
	popq   %rsi; \
	popq   %rdx; \
	popq   %rcx; \
	popq   %r8; \
	popq   %r9; \
	addq    $16, %rsp; \
	popq   %rbx; \
	popq   %rbp; \
	popq   %r12; \
	popq   %r13; \
	popq   %r14; \
	popq   %r15; \
	popq   %rax; \

#define CALL_SYSCALL_FUNC(sysnr_reg, scratch_reg) \
	shlq    $3, sysnr_reg; \
	leaq    sys_tbl(%rip), scratch_reg; \
	addq    scratch_reg, sysnr_reg; \
	callq   *(%rax);


/*
 * junction_fncall_enter - main entry point for system calls.
 * This routine saves the trapframe at entry on the stack and stores a pointer
 * in the thread struct. This enables the system call to be restarted easily at
 * a later point. Before returning, checks/applies pending signals.
 */
.align 16
.globl junction_fncall_enter
.type junction_fncall_enter, @function
junction_fncall_enter:

	// align stack
	subq $8, %rsp

	// get return IP
	movq 8(%rsp), %r11

	// save rax to orig_rax
	pushq %rax

	// push return stack pointer
	leaq  24(%rsp), %r10
	pushq %r10

	// push return IP
	pushq   %r11

	SAVETF_STACK_AND_MARK_SYSCALL

	CALL_SYSCALL_FUNC(%rax, %r11)

	// save the return value
	movq %rax, RAX(%rsp)

1:
	movq    %gs:__perthread___self(%rip), %r11
	movb    $0, JUNCTION_IN_SYSCALL_OFF(%r11)

	// check for interrupts
	movl    JUNCTION_INT_STATE_OFF(%r11), %edi
	test    %edi, %edi
	jg      2f

	addq    $(19 * 8), %rsp // remove 18 registers on stack plus alignment
	ret

2:
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)
	movq    %rax, %rdi
	call    RunSignals
	movq 	RAX(%rsp), %rax
	jmp     1b

/*
 * junction_fncall_stackswitch_enter - entry point for runtimes that require
 * system calls to run on separate stacks.
 */
.align 16
.globl junction_fncall_stackswitch_enter
.type junction_fncall_stackswitch_enter, @function
junction_fncall_stackswitch_enter:

	// Mark begin syscall, *before* starting to use the syscall stack
	movq 	%gs:__perthread___self(%rip), %r11
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)

	// Find bottom of syscall stack
	movq    JUNCTION_STACK_OFFSET(%r11), %r11

	// subtract 16 to (A) leave space for unused fsbase field in trapframe
	// and (B) ensure correct alignment for the next call
	addq    $(JUNCTION_STACK_SIZE - 16), %r11

	// push orig_rax
	movq 	%rax, -8(%r11)

	// push return stack pointer
	leaq  8(%rsp), %r10
	movq  %r10, -16(%r11)

	// push RIP to new stack
	movq    (%rsp), %r10
	movq    %r10, -24(%r11)

	// switch to new stack
	leaq    -24(%r11), %rsp

	SAVETF_STACK
	CALL_SYSCALL_FUNC(%rax, %r11)

	// store return value in trapframe
	movq    %rax, RAX(%rsp)

1:
	movq 	%gs:__perthread___self(%rip), %r11
	movb    $0, JUNCTION_IN_SYSCALL_OFF(%r11)

	// check for interrupts
	movl    JUNCTION_INT_STATE_OFF(%r11), %edi
	test    %edi, %edi
	jg      2f

	// restore stack pointer
	movq 	RSP(%rsp), %rsp
	subq    $8, %rsp
	ret

2:
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)
	movq    %rax, %rdi
	call    RunSignals
	movq    RAX(%rsp), %rax
	jmp     1b

/*
 * junction_fncall_enter_preserve_regs - variant of junction_fncall_enter that
 * preserves argument registers. This is needed for vfork/clone/clone3.
 */
.align 16
.globl junction_fncall_enter_preserve_regs
.type junction_fncall_enter_preserve_regs, @function
junction_fncall_enter_preserve_regs:

	// align stack
	subq $8, %rsp

	// get return IP
	movq 8(%rsp), %r11

	// save rax to orig_rax
	pushq %rax

	// push return stack pointer
	leaq  24(%rsp), %r10
	pushq %r10

	// push return IP
	pushq   %r11

	SAVETF_STACK_AND_MARK_SYSCALL

	CALL_SYSCALL_FUNC(%rax, %r11)

	// save the return value
	movq %rax, RAX(%rsp)

1:
	movq    %gs:__perthread___self(%rip), %r11
	movb    $0, JUNCTION_IN_SYSCALL_OFF(%r11)

	// check for interrupts
	movl    JUNCTION_INT_STATE_OFF(%r11), %edi
	test    %edi, %edi
	jg      2f

	RESTORETF_STACK
	addq    $(4 * 8), %rsp // remove rsp, rip, and orig_rax, alignment
	ret

2:
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)
	movq    %rax, %rdi
	call    RunSignals
	movq 	RAX(%rsp), %rax
	jmp     1b

/*
 * junction_fncall_stackswitch_enter_preserve_regs - variant of
 * junction_fncall_stackswitch_enter that preserves argument registers. This is
 * needed for vfork/clone/clone3.
 */

.globl junction_fncall_stackswitch_enter_preserve_regs
.type junction_fncall_stackswitch_enter_preserve_regs, @function
.globl __fncall_return_exit_loop

.align 16
junction_fncall_stackswitch_enter_preserve_regs:

	// Mark begin syscall, *before* starting to use the syscall stack
	movq 	%gs:__perthread___self(%rip), %r11
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)

	// Find bottom of syscall stack
	movq    JUNCTION_STACK_OFFSET(%r11), %r11

	// subtract 16 to (A) leave space for unused fsbase field in trapframe
	// and (B) ensure correct alignment for the next call
	addq    $(JUNCTION_STACK_SIZE - 16), %r11

	// push orig_rax
	movq 	%rax, -8(%r11)

	// push return stack pointer
	leaq  8(%rsp), %r10
	movq  %r10, -16(%r11)

	// push RIP to new stack
	movq    (%rsp), %r10
	movq    %r10, -24(%r11)

	// switch to new stack
	leaq    -24(%r11), %rsp

	SAVETF_STACK
	CALL_SYSCALL_FUNC(%rax, %r11)

	// store return value in trapframe
	movq    %rax, RAX(%rsp)

__fncall_return_exit_loop:
	movq 	%gs:__perthread___self(%rip), %r11
	movb    $0, JUNCTION_IN_SYSCALL_OFF(%r11)

	// check for interrupts
	movl    JUNCTION_INT_STATE_OFF(%r11), %edi
	test    %edi, %edi
	jg      1f

	RESTORETF_STACK
	add $8, %rsp // ignore rip
	popq %rsp // restore rsp
	subq    $8, %rsp

	ret

1:
	movb    $1, JUNCTION_IN_SYSCALL_OFF(%r11)
	movq    %rax, %rdi
	call    RunSignals
	jmp     __fncall_return_exit_loop
