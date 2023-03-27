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
#include "junction/kernel/mm.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/limits.h"
#include "junction/syscall/entry.h"
#include "junction/syscall/syscall.h"

namespace junction {

namespace {

// Global allocation of PIDs
rt::Spin process_lock;
UIDGenerator<kMaxProcesses> pid_generator;

void CopyCalleeRegs(thread_tf &newtf, const thread_tf &oldtf) {
  newtf.rbx = oldtf.rbx;
  newtf.rbp = oldtf.rbp;
  newtf.r12 = oldtf.r12;
  newtf.r13 = oldtf.r13;
  newtf.r14 = oldtf.r14;
  newtf.r15 = oldtf.r15;
}

void CopyCallerRegs(thread_tf &newtf, const thread_tf &oldtf) {
  newtf.rdi = oldtf.rdi;
  newtf.rsi = oldtf.rsi;
  newtf.rdx = oldtf.rdx;
  newtf.rcx = oldtf.rcx;
  newtf.r8 = oldtf.r8;
  newtf.r9 = oldtf.r9;
  newtf.r10 = oldtf.r10;
}

void CloneTrapframe(thread_t *newth, const thread_t *oldth) {
  CopyCalleeRegs(newth->tf, oldth->junction_tf);
  CopyCallerRegs(newth->junction_tf, oldth->junction_tf);
  newth->junction_tf.rip = oldth->junction_tf.rip;

  // copy fsbase if present
  if (oldth->has_fsbase) {
    newth->has_fsbase = true;
    newth->tf.fsbase = oldth->tf.fsbase;
  }

  if (oldth->xsave_area) {
    newth->tf.rip =
        reinterpret_cast<uint64_t>(__junction_syscall_intercept_clone_ret);
    newth->junction_tf.rsp = newth->tf.rsp;
    newth->tf.rsp = AlignDown(newth->tf.rsp - XSAVE_BYTES, 64);
    std::memcpy(reinterpret_cast<void *>(newth->tf.rsp), oldth->xsave_area,
                XSAVE_BYTES);
  } else {
    newth->tf.rip = reinterpret_cast<uint64_t>(clone_fast_start);
  }
}

long DoClone(clone_args *cl_args, uint64_t rsp) {
  static constexpr uint64_t kRequiredFlags =
      (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD);

  // Only support starting new threads in the same process
  if ((cl_args->flags & kRequiredFlags) != kRequiredFlags) return -ENOSYS;

  thread_t *th = thread_create_nostack(nullptr, 0);
  if (!th) return -ENOMEM;
  th->tf.rsp = rsp;

  // Allocate some stack space for some of our thread-local data
  Thread &tstate = myproc().CreateThread(th);

  // Clone the trap frame
  CloneTrapframe(th, thread_self());

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

}  // namespace

Status<Process *> CreateProcess() {
  pid_t pid;
  {
    rt::SpinGuard guard(process_lock);
    std::optional<size_t> tmp = pid_generator();
    if (!tmp) return MakeError(ENOSPC);
    pid = *tmp;
  }

  Status<void *> base = CreateMemoryMap(kMemoryMappingSize);
  if (!base) return MakeError(base);

  LOG(INFO) << "proc: Creating process with pid=" << pid
            << ", mapping=" << *base << "-"
            << reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(*base) +
                                        kMemoryMappingSize);
  return new Process(pid, *base, kMemoryMappingSize);
}

// Attach calling thread to this process; used for testing.
Thread &Process::CreateTestThread() {
  // Intentionally leak this memory
  thread_t *th = thread_self();
  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(this, 1);
  th->tlsvar = 1;  // Mark tstate as initialized
  return *tstate;
}

Thread &Process::CreateThread(thread_t *th) {
  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(this, 1);  // TODO: make PID unique?
  th->tlsvar = 1;                // Mark tstate as initialized
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

long usys_clone3(clone_args *cl_args, size_t size) {
  if (unlikely(!cl_args->stack)) return -EINVAL;
  return DoClone(cl_args, cl_args->stack + cl_args->stack_size);
}

long usys_clone(unsigned long clone_flags, unsigned long newsp,
                uintptr_t parent_tidptr, uintptr_t child_tidptr,
                unsigned long tls) {
  clone_args cl_args;
  cl_args.flags = clone_flags;
  cl_args.child_tid = child_tidptr;
  cl_args.parent_tid = parent_tidptr;
  cl_args.tls = tls;
  return DoClone(&cl_args, newsp);
}

void usys_exit(int status) {
  Thread &tstate = mythread();
  uint32_t *child_tid = tstate.get_child_tid();
  if (child_tid) {
    *child_tid = 0;
    FutexTable::GetFutexTable().Wake(child_tid, 1);
  }

  Thread *tptr = reinterpret_cast<Thread *>(thread_self()->junction_tstate_buf);
  tptr->~Thread();

  rt::Exit();
}

void usys_exit_group(int status) {
  LOG(ERR) << "Exiting...";
  // TODO(jfried): this should only terminate this Proc
  ksys_exit(status);
}

}  // namespace junction
