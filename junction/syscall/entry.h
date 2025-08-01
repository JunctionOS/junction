// entry.h - definitions for entry.S

#pragma once

#define CALADAN_TF_OFF 112
#define JUNCTION_STACK_OFFSET 80
#define JUNCTION_STACK_SIZE (512 * 1024 * 2)
#define JUNCTION_STACK_RESERVED (24 * 1024)
#define JUNCTION_TF_PTR_OFF 8
#define JUNCTION_IN_SYSCALL_OFF 3
#define JUNCTION_INT_STATE_OFF 5

#define SIGFRAME_RAX_OFFSET 0x90
#define SIGFRAME_SIGCONTEXT 40
#define SIGCONTEXT_EFLAGS 136
#define SIGCONTEXT_XSTATE 184

#define XSAVE_PTR 120

#define SIGCONTEXT_R8 0
#define SIGCONTEXT_R9 8
#define SIGCONTEXT_R10 16
#define SIGCONTEXT_R11 24
#define SIGCONTEXT_R12 32
#define SIGCONTEXT_R13 40
#define SIGCONTEXT_R14 48
#define SIGCONTEXT_R15 56
#define SIGCONTEXT_RDI 64
#define SIGCONTEXT_RSI 72
#define SIGCONTEXT_RBP 80
#define SIGCONTEXT_RBX 88
#define SIGCONTEXT_RDX 96
#define SIGCONTEXT_RAX 104
#define SIGCONTEXT_RCX 112
#define SIGCONTEXT_RSP 120
#define SIGCONTEXT_RIP 128
