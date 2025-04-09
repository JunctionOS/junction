
/*
 * switch.S - assembly routines for switching stacks
 */

.file "switch.S"
.section        .note.GNU-stack,"",@progbits
.text

/**
 * __nosave_switch_preempt_enable - jumps to a function without saving the current stack
 * frame, and re-enables preemption.
 * @fn: the function pointer to call (%rdi)
 * @stack: the stack to use (%rsi)
 * @arg0: an argument to @fn (%rdx)
 *
 * No return value.
 */
.align 16
.globl __nosave_switch_preempt_enable
.type __nosave_switch_preempt_enable, @function
__nosave_switch_preempt_enable:
	/* switch to new stack */
	movq	%rsi, %rsp

	/* move fn to temporary register */
	movq	%rdi, %r11

	/* setup args */
	movq	%rdx, %rdi

	/* re-enable preemption */
	subl	$1, %gs:__perthread_preempt_cnt(%rip)
	jz		1f

	/* jump to fn */
	jmpq	*%r11
	nop

1:
	pushq	%r11
	pushq	%rdi
	movq	%rsp, %r15
	andq	$-16, %rsp
	call	preempt
	movq	%r15, %rsp
	popq	%rdi
	popq	%r11
	jmpq	*%r11

/**
 * __nosave_switch - jumps to a function without saving the current stack
 * frame.
 * @fn: the function pointer to call (%rdi)
 * @stack: the stack to use (%rsi)
 * @arg0: an argument to @fn (%rdx)
 *
 * No return value.
 */
.align 16
.globl __nosave_switch
.type __nosave_switch, @function
__nosave_switch:
	/* switch to new stack */
	movq    %rsi, %rsp

	/* move fn to temporary register */
	movq    %rdi, %rsi

	/* setup arg0 */
	movq    %rdx, %rdi

	/* jump to fn */
	jmpq    *%rsi

/**
 * __nosave_switch_setui - jumps to a function without saving the current stack
 * frame and re-enables user interrupts once on the new stack.
 * @fn: the function pointer to call (%rdi)
 * @stack: the stack to use (%rsi)
 * @arg0: an argument to @fn (%rdx)
 *
 * No return value.
 */
.align 16
.globl __nosave_switch_setui
.type __nosave_switch_setui, @function
__nosave_switch_setui:
	/* switch to new stack */
	movq    %rsi, %rsp

	movq    %rdi, %rsi
	movq    %rdx, %rdi

	/* enable interrupts */
	stui

	/* jump to fn */
	jmpq    *%rsi

/*
 * _stack_switch_link - runs a function on a different stack
 * @arg0: an argument to pass to @fn (%rdi)
 * @stack: the start of the runtime stack (%rsi)
 * @fn: the function pointer to call (%rdx)
 *
 */
.align 16
.globl _stack_switch_link
.type _stack_switch_link, @function
_stack_switch_link:
	.cfi_startproc
	pushq    %r15 # save r15
	.cfi_adjust_cfa_offset 8      # Adjust CFA to account for pushed r15
	.cfi_rel_offset %r15, 0       # The value of r15 is at sp(0)

	movq    %rsp, %r15
	.cfi_def_cfa_register %r15    # r15 contains the frame location

	movq    %rsi, %rsp
	subq    $8, %rsp
	callq   *%rdx
	movq    %r15, %rsp
	.cfi_def_cfa_register %rsp    # rsp contains the frame location

	popq    %r15
	.cfi_restore r15              # Restore r15 from its saved location
	.cfi_adjust_cfa_offset -8     # Adjust CFA to account for popped r15

	ret
	.cfi_endproc