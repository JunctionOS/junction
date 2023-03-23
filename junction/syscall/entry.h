// entry.h - definitions for entry.S

#pragma once

#define JUNCTION_TF_OFF 216
#define JUNCTION_XSAVEPTR_OFF 360
#define JUNCTION_STACK_OFFSET 160
#define JUNCTION_STACK_SIZE (512 * 1024 * 2)
#define XSAVE_BYTES 4096  // TODO(jsf): fix
