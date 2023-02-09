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
#include "junction/kernel/futex.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

// Attach calling thread to this process; used for testing.
Thread &Process::CreateTestThread() {
  // Intentionally leak this memory
  Thread *tstate = new Thread(this, 1);
  __set_uthread_specific(thread_self(), reinterpret_cast<uintptr_t>(tstate));
  return *tstate;
}

Thread &Process::CreateThread(thread_t *th) {
  // Store the Thread object on the stack
  th->tf.rsp = AlignDown(th->tf.rsp - sizeof(Thread), 16);
  __set_uthread_specific(th, th->tf.rsp);
  Thread *tstate = reinterpret_cast<Thread *>(th->tf.rsp);
  new (tstate) Thread(this, 1);  // TODO: make PID unique?
  return *tstate;
}

pid_t usys_getpid() { return myproc().get_pid(); }

int usys_arch_prctl(int code, unsigned long addr) {
  if (code != ARCH_SET_FS) return -EINVAL;
  set_fsbase(thread_self(), addr);
  return 0;
}

pid_t usys_set_tid_address(int *tidptr) {
  Thread &tstate = mythread();
  tstate.set_child_tid(reinterpret_cast<uint32_t *>(tidptr));
  return tstate.get_tid();
}

// Take advantage of the fact that glibc places func/arg in the 3rd/4th argument
// register (SYS_clone3 only uses the first two arguments). The new
// thread starts with the same RIP and registers but with a different return
// value from the parent thread, and branches to the function in the 3rd
// argument register. Instead of cloning the existing thread, we just start the
// child directly at func. See __clone3 in clone3.S in glibc for reference.
long usys_clone3(clone_args *cl_args, size_t size, int (*func)(void *arg),
                 void *arg) {
  static constexpr uint64_t kRequiredFlags =
      (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD);

  // Only support starting new threads in the same process
  if ((cl_args->flags & kRequiredFlags) != kRequiredFlags) return -ENOSYS;

  // We may have entered here from either a patched glibc or from a syscall trap
  // If we are in a syscall trap, we need to look elsewhere for @arg
  // TODO: this really only works for glibc.
  if (mythread().get_tf())
    arg = reinterpret_cast<void *>(
        mythread().get_tf()->uc_mcontext.gregs[REG_R8]);

  thread_t *th;
  if (cl_args->stack) {
    th = thread_create_nostack(reinterpret_cast<thread_fn_t>(func), arg);
    if (!th) return -ENOMEM;
    th->tf.rsp = cl_args->stack + cl_args->stack_size;
  } else {
    th = thread_create(reinterpret_cast<thread_fn_t>(func), arg);
    if (!th) return -ENOMEM;
    th->tf.rsp += 8;
  }

  // Allocate some stack space for some of our thread-local data
  Thread &tstate = myproc().CreateThread(th);

  // New function expects stack to be aligned to 8 mod 16.
  assert(th->tf.rsp % 16 == 0);
  th->tf.rsp -= 8;

  // Set FSBASE if requested
  if (cl_args->flags & CLONE_SETTLS) set_fsbase(th, cl_args->tls);

  // Write this thread's tid into
  if (cl_args->flags & CLONE_PARENT_SETTID)
    *reinterpret_cast<uint32_t *>(cl_args->parent_tid) = tstate.get_tid();

  // Save a pointer to the child_tid address if requested, so it can later
  // notify the parent of the child's exit via futex.
  if (cl_args->flags & CLONE_CHILD_CLEARTID)
    tstate.set_child_tid(reinterpret_cast<uint32_t *>(cl_args->child_tid));
  else
    tstate.set_child_tid(nullptr);

  thread_ready(th);
  return tstate.get_tid();
}

void usys_exit(int status) {
  Thread &tstate = mythread();
  uint32_t *child_tid = tstate.get_child_tid();
  if (child_tid) {
    *child_tid = 0;
    FutexTable::GetFutexTable().Wake(child_tid, 1);
  }
  rt::Exit();
}

void usys_exit_group(int status) {
  LOG(ERR) << "Exiting...";
  // TODO(jfried): this should only terminate this Proc
  ksys_exit(status);
}

}  // namespace junction
