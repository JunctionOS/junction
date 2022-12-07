
extern "C" {
// Use only for defs...
#include "lib/caladan/runtime/defs.h"
}

#include <dlfcn.h>
#include <pthread.h>

#include <cstring>
#include <iostream>

#include "junction/shim/shim.h"

namespace junction {

struct pthread_attr_internal {
  /* Scheduler parameters and priority.  */
  struct sched_param schedparam;
  int schedpolicy;
  /* Various flags like detachstate, scope, etc.  */
  int flags;
  /* Size of guard area.  */
  size_t guardsize;
  /* Stack handling.  */
  void *stackaddr;
  size_t stacksize;

  /* Allocated via a call to __pthread_attr_extension once needed.  */
  void *extension;
  void *unused;
};

#define ATTR_FLAG_STACKADDR 0x0008

extern "C" int pthread_detach(pthread_t thread) {
  // TODO(jf): Fix.
  return ENOTSUP;
}

extern "C" int pthread_join(pthread_t threadid, void **thread_return) {
  static typeof(pthread_join) *fn;
  if (unlikely(!fn)) {
    fn = (typeof(pthread_join) *)dlsym(RTLD_NEXT, "pthread_join");
    if (!fn) return ENOSYS;
  }

  pthread_attr_t attr;
  int ret = pthread_getattr_np(threadid, &attr);
  if (unlikely(ret)) {
    std::cerr << "pthread_getattr_np failed " << ret << std::endl;
    return ret;
  }

  void *stackaddr;
  size_t stacksize;
  ret = pthread_attr_getstack(&attr, &stackaddr, &stacksize);
  if (unlikely(ret)) {
    std::cerr << "pthread_attr_getstack failed " << ret << std::endl;
    return ret;
  }

  static_assert(offsetof(stack, usable) == 0);
  stack *stk = reinterpret_cast<stack *>(stackaddr);
  ret = fn(threadid, thread_return);
  free_stack(stk);
  return ret;
}

extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *_attr,
                              void *(*start_routine)(void *), void *arg) {
  union {
    pthread_attr_internal iattr;
    pthread_attr_t attr;
  };

  std::memset(&attr, 0, sizeof(attr));

  stack *stack = allocate_stack();
  if (unlikely(!stack)) {
    std::cerr << "failed to allocate stack" << std::endl;
    return ENOMEM;
  }

  static_assert(offsetof(struct stack, usable) == 0);

  iattr.stackaddr = (unsigned char *)stack + RUNTIME_STACK_SIZE;
  iattr.stacksize = RUNTIME_STACK_SIZE;
  iattr.guardsize = RUNTIME_GUARD_SIZE;
  iattr.flags = ATTR_FLAG_STACKADDR;

  static typeof(pthread_create) *fn;
  if (unlikely(!fn)) {
    fn = (typeof(pthread_create) *)dlsym(RTLD_NEXT, "pthread_create");
    if (!fn) {
      std::cerr << "failed to find pthread_create" << std::endl;
      return ENOSYS;
    }
  }

  return fn(thread, reinterpret_cast<pthread_attr_t *>(&iattr), start_routine,
            arg);
}
}  // namespace junction
