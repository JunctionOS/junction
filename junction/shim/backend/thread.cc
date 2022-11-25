
extern "C" {
#include "lib/caladan/runtime/defs.h"
}

#include "junction/base/error.h"
#include "junction/shim/shim.h"

namespace junction {

struct stack *shim_allocate_stack() {
  return stack_alloc();
}

void shim_free_stack(struct stack *stack) { stack_free(stack); }

}  // namespace junction