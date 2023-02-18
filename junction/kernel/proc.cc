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
#include <cstring>

#include "junction/base/arch.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/futex.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/syscall/entry.h"
#include "junction/syscall/syscall.h"

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

void CloneTrapframe(thread_t *oldth, thread_t *newth) {
  // copy callee saved regs from oldth->junction_tf to newth->tf
  thread_tf &newtf = newth->tf;
  thread_tf &oldtf = oldth->junction_tf;
  newtf.rbx = oldtf.rbx;
  newtf.rbp = oldtf.rbp;
  newtf.r12 = oldtf.r12;
  newtf.r13 = oldtf.r13;
  newtf.r14 = oldtf.r14;
  newtf.r15 = oldtf.r15;

  // copy fsbase if present
  if (oldth->has_fsbase) {
    newth->has_fsbase = true;
    newtf.fsbase = oldth->tf.fsbase;
  }

  // copy extra state if we came in via trap
  if (oldth->xsave_area) {
    // copy caller saved regs from oldth->junction_tf to newth->junction_tf
    thread_tf &newjtf = newth->junction_tf;
    newjtf.rdi = oldtf.rdi;
    newjtf.rsi = oldtf.rsi;
    newjtf.rcx = oldtf.rcx;
    newjtf.rdx = oldtf.rdx;
    newjtf.r8 = oldtf.r8;
    newjtf.r9 = oldtf.r9;
    newjtf.r10 = oldtf.r10;

    // Our return routine expects xsave area on the stack, and the future
    // stack addr provided in rdi.
    newtf.rip = reinterpret_cast<uint64_t>(junction_full_restore_newth);
    newtf.rdi = newtf.rsp;

    // allocate xsave area on stack
    newtf.rsp = AlignDown(newtf.rsp - XSAVE_BYTES, 64);

    // Copy the xsave area
    std::memcpy(reinterpret_cast<void *>(newtf.rsp), oldth->xsave_area,
                XSAVE_BYTES);
  } else {
    // fast return without restoring extended reg set
    newtf.rdi = oldtf.rip;
    newtf.rip = reinterpret_cast<uint64_t>(clone_fast_start);
  }
}

long usys_clone3(clone_args *cl_args, size_t size, int (*func)(void *arg),
                 void *arg) {
  static constexpr uint64_t kRequiredFlags =
      (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD);

  // Only support starting new threads in the same process
  if ((cl_args->flags & kRequiredFlags) != kRequiredFlags) return -ENOSYS;

  thread_t *th;
  if (cl_args->stack) {
    th = thread_create_nostack(nullptr, 0);
    if (!th) return -ENOMEM;
    th->tf.rsp = cl_args->stack + cl_args->stack_size;
  } else {
    th = thread_create(nullptr, 0);
    if (!th) return -ENOMEM;
    th->tf.rsp += 8;
  }

  // Allocate some stack space for some of our thread-local data
  Thread &tstate = myproc().CreateThread(th);

  // Clone the trap frame
  CloneTrapframe(thread_self(), th);

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
