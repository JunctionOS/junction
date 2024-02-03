// entry.h - definitions for entry.S

#pragma once

#define CALADAN_TF_OFF 216
#define JUNCTION_STACK_OFFSET 192
#define JUNCTION_STACK_SIZE (512 * 1024 * 2)
#define JUNCTION_STACK_RESERVED (24 * 1024)
#define JUNCTION_TF_PTR_OFF 8
#define JUNCTION_IN_SYSCALL_OFF 3
#define JUNCTION_INT_STATE_OFF 5

#define SIGFRAME_RAX_OFFSET 0x90
#define SIGFRAME_RIP_OFFSET 0xa8
#define SIGFRAME_RSP_OFFSET 0xa0
#define SIGFRAME_RFLAGS_OFFSET 0xb0
