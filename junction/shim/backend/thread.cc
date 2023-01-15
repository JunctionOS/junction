
extern "C" {
#include "lib/caladan/runtime/defs.h"
}

#include "junction/shim/shim.h"

namespace junction {

int shim_allocate_stack(void **stack_bottom_out, size_t *stack_size_out,
                        size_t *guard_size_out) {
  stack *stack = stack_alloc();
  if (unlikely(!stack)) return -ENOMEM;

  *stack_bottom_out = (unsigned char *)stack->usable + RUNTIME_STACK_SIZE;
  *stack_size_out = RUNTIME_STACK_SIZE;
  *guard_size_out = RUNTIME_GUARD_SIZE;

  return 0;
}

void shim_free_stack(void *stack_top) {
  auto uptr = reinterpret_cast<uintptr_t(*)[STACK_PTR_SIZE]>(stack_top);
  stack *stk = container_of(uptr, stack, usable);
  stack_free(stk);
}

void shim_free_stack_on_exit(void *stack_top) {
  auto uptr = reinterpret_cast<uintptr_t(*)[STACK_PTR_SIZE]>(stack_top);
  stack *stk = container_of(uptr, stack, usable);
  /* attach this stack to the struct thread, caladan's scheduler will free */
  assert(thread_self()->stack == nullptr);
  thread_self()->stack = stk;
}

}  // namespace junction