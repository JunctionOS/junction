extern "C" {
#include <asm/prctl.h>
#include <linux/futex.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "lib/caladan/runtime/defs.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/sched.h>
}

#include <cstdlib>

#include "junction/base/arch.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

pid_t usys_getpid() { return 0; }

int usys_arch_prctl(int code, unsigned long addr) {
  if (code != ARCH_SET_FS) return -EINVAL;

  set_fsbase(thread_self(), addr);

  return 0;
}

pid_t usys_set_tid_address(int *tidptr) {
  ThreadState *tstate = mystate();
  tstate->child_tid = reinterpret_cast<uint32_t *>(tidptr);
  return tstate->tid;
}

ThreadState *Proc::ProcSetupNewThread(thread_t *th) {
  // Add a ThreadState to the stack
  th->tf.rsp = AlignDown(th->tf.rsp - sizeof(ThreadState), 16);
  __set_uthread_specific(th, th->tf.rsp);
  ThreadState *tstate = reinterpret_cast<ThreadState *>(th->tf.rsp);
  tstate->proc = this;
  tstate->tid = 1;  // TODO: make unique?
  return tstate;
}

#define REQUIRED_CLONE_FLAGS (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD)

// Take advantage of the fact that glibc places func/arg in the 3rd/4th argument
// register (SYS_clone3 only uses the first two arguments). The new
// thread starts with the same RIP and registers but with a different return
// value from the parent thread, and branches to the function in the 3rd
// argument register. Instead of cloning the existing thread, we just start the
// child directly at func. See __clone3 in clone3.S in glibc for reference.
long usys_clone3(clone_args *cl_args, size_t size, int (*func)(void *arg),
                 void *arg) {
  // Only support starting new threads in the same process
  if ((cl_args->flags & REQUIRED_CLONE_FLAGS) != REQUIRED_CLONE_FLAGS)
    return -ENOSYS;

  thread_t *th = thread_create(reinterpret_cast<thread_fn_t>(func), arg);
  if (!th) return -ENOMEM;

  // Allocate some stack space for some of our thread-local data
  // Remove existing pointer to caladan's thread_exit, threads here will do a
  // syscall(SYS_exit).
  th->tf.rsp += 8;
  ThreadState *tstate = myproc()->ProcSetupNewThread(th);

  // Use a library-provided stack
  if (cl_args->stack) th->tf.rsp = cl_args->stack + cl_args->stack_size;

  // New function expects stack to be aligned to 8 mod 16.
  assert(th->tf.rsp % 16 == 0);
  th->tf.rsp -= 8;

  // Set FSBASE if requested
  if (cl_args->flags & CLONE_SETTLS) set_fsbase(th, cl_args->tls);

  // Write this thread's tid into
  if (cl_args->flags & CLONE_PARENT_SETTID)
    *reinterpret_cast<uint32_t *>(cl_args->parent_tid) = tstate->tid;

  // Save a pointer to the child_tid address if requested, so it can later
  // notify the parent of the child's exit via futex.
  if (cl_args->flags & CLONE_CHILD_CLEARTID)
    tstate->child_tid = reinterpret_cast<uint32_t *>(cl_args->child_tid);
  else
    tstate->child_tid = 0;

  thread_ready(th);
  return tstate->tid;
}

void usys_exit(int status) {
  ThreadState *ts = mystate();
  if (ts->child_tid) {
    *ts->child_tid = 0;
    usys_futex(ts->child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
  }

  rt::Exit();
}

void usys_exit_group(int status) {
  LOG(ERR) << "Exiting...";
  // TODO(jfried): this should only terminate this Proc
  ksys_exit(status);
}

}  // namespace junction
