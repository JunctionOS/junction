
/*
 * switch.S - assembly routines for switching stacks
 */

.file "switch.S"
.section        .note.GNU-stack,"",@progbits
.text

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