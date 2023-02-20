// entry.h - definitions for entry.S

#pragma once

#define JUNCTION_TF_OFF 208
#define JUNCTION_XSAVEPTR_OFF 352
#define JUNCTION_STACK_OFFSET 160
#define JUNCTION_STACK_SIZE (512 * 1024 * 2)
#define REDZONE_SIZE 128
#define XSAVE_BYTES 4096  // TODO(jsf): fix
