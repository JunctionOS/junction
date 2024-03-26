
/*
 * switch.S - assembly routines for switching stacks
 */

.file "switch.S"
.section        .note.GNU-stack,"",@progbits
.text

/**
 * nosave_switch_preempt_enable - jumps to a function without saving the current stack
 * frame, and re-enables preemption.
 * @fn: the function pointer to call (%rdi)
 * @stack: the stack to use (%rsi)
 * @arg0: an argument to @fn (%rdx)
 *
 * No return value.
 */
.align 16
.globl nosave_switch_preempt_enable
.type nosave_switch_preempt_enable, @function
nosave_switch_preempt_enable:
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
 * nosave_switch - jumps to a function without saving the current stack
 * frame.
 * @fn: the function pointer to call (%rdi)
 * @stack: the stack to use (%rsi)
 * @arg0: an argument to @fn (%rdx)
 *
 * No return value.
 */
.align 16
.globl nosave_switch
.type nosave_switch, @function
nosave_switch:
	/* switch to new stack */
	movq    %rsi, %rsp

	/* move fn to temporary register */
	movq    %rdi, %rsi

	/* setup arg0 */
	movq    %rdx, %rdi

	/* jump to fn */
	jmpq    *%rsi

/**
 * nosave_switch_setui - jumps to a function without saving the current stack
 * frame and re-enables user interrupts once on the new stack.
 * @fn: the function pointer to call (%rdi)
 * @stack: the stack to use (%rsi)
 *
 * No return value.
 */
.align 16
.globl nosave_switch_setui
.type nosave_switch_setui, @function
nosave_switch_setui:
	/* switch to new stack */
	movq    %rsi, %rsp

	/* enable interrupts */
	stui

	/* jump to fn */
	jmpq    *%rdi