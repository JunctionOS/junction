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
#include "junction/junction.h"
#include "junction/kernel/futex.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/limits.h"
#include "junction/syscall/entry.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"

namespace junction {

namespace {

// Global allocation of PIDs
rt::Spin process_lock;
UIDGenerator<kMaxProcesses> pid_generator;

Status<pid_t> AllocPid() {
  rt::SpinGuard guard(process_lock);
  std::optional<size_t> tmp = pid_generator();
  if (!tmp) return MakeError(ENOSPC);
  return *tmp;
}

void ReleasePid(pid_t pid) {
  rt::SpinGuard guard(process_lock);
  pid_generator.Release(pid);
}

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

  newth->tf.rip = reinterpret_cast<uint64_t>(clone_fast_start);
}

long DoClone(clone_args *cl_args, uint64_t rsp) {
  static constexpr uint64_t kThreadRequiredFlags =
      (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD | CLONE_SIGHAND);

  static constexpr uint64_t kVforkRequiredFlags = (CLONE_VM | CLONE_VFORK);

  static constexpr uint64_t kCheckFlags =
      (kThreadRequiredFlags | kVforkRequiredFlags);

  bool do_vfork = false;

  switch (cl_args->flags & kCheckFlags) {
    case kVforkRequiredFlags:
      do_vfork = true;
      break;
    case kThreadRequiredFlags:
      break;
    default:
      return -ENOSYS;
  }

  Status<std::unique_ptr<Thread>> tptr;

  if (do_vfork) {
    rt::ThreadWaker waker;
    waker.Arm();
    Status<std::shared_ptr<Process>> forkp =
        myproc().CreateProcessVfork(std::move(waker));
    if (!forkp) return MakeCError(forkp);
    tptr = (*forkp)->CreateThread();
  } else {
    tptr = myproc().CreateThread();
  }

  if (!tptr) return MakeCError(tptr);

  Thread &tstate = **tptr;
  thread_t *th = tstate.GetCaladanThread();

  th->tf.rsp = rsp;

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

  (*tptr).release();
  thread_ready(th);

  // Wait for child thread to exit or exec
  if (do_vfork) rt::WaitForever();

  return tstate.get_tid();
}

}  // namespace

rt::WaitGroup Process::all_procs;

Thread::~Thread() {
  uint32_t *child_tid = get_child_tid();
  if (child_tid) {
    *child_tid = 0;
    FutexTable::GetFutexTable().Wake(child_tid);
  }
  proc_->ThreadFinish(this);
  if (tid_ != proc_->get_pid()) ReleasePid(tid_);
}

Process::~Process() {
  vfork_waker_.Wake();
  ReleasePid(pid_);
  all_procs.Done();
}

void Process::FinishExec(std::shared_ptr<MemoryMap> &&new_mm) {
  file_tbl_.DoCloseOnExec();
  mem_map_ = std::move(new_mm);
  vfork_waker_.Wake();
}

void Process::ThreadFinish(Thread *th) {
  rt::SpinGuard g(thread_map_lock_);
  thread_map_.erase(th->get_tid());
}

Status<std::shared_ptr<Process>> CreateProcess() {
  Status<pid_t> pid = AllocPid();
  if (!pid) return MakeError(pid);

  Status<std::shared_ptr<MemoryMap>> mm = CreateMemoryMap(kMemoryMappingSize);
  if (!mm) return MakeError(mm);

  const void *base = (*mm)->get_base();
  LOG(INFO) << "proc: Creating process with pid=" << *pid
            << ", mapping=" << base << "-"
            << reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base) +
                                        kMemoryMappingSize);
  return std::make_shared<Process>(*pid, std::move(*mm));
}

Status<std::shared_ptr<Process>> Process::CreateProcessVfork(
    rt::ThreadWaker &&w) {
  Status<pid_t> pid = AllocPid();
  if (!pid) return MakeError(pid);

  return std::make_shared<Process>(*pid, mem_map_, file_tbl_, std::move(w));
}

// Attach calling thread to this process; used for testing.
Thread &Process::CreateTestThread() {
  thread_t *th = thread_self();
  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), 1);
  th->tlsvar = 1;  // Mark tstate as initialized
  thread_map_[1] = tstate;
  return *tstate;
}

Status<std::unique_ptr<Thread>> Process::CreateThreadMain() {
  thread_t *th = thread_create(nullptr, 0);
  if (!th) return MakeError(ENOMEM);

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), get_pid());
  th->tlsvar = 1;  // Mark tstate as initialized
  thread_map_[get_pid()] = tstate;
  return std::unique_ptr<Thread>(tstate);
}

Status<std::unique_ptr<Thread>> Process::CreateThread() {
  thread_t *th = thread_create_nostack(nullptr, 0);
  if (unlikely(!th)) return MakeError(ENOMEM);

  Status<pid_t> tid = AllocPid();
  if (!tid) {
    thread_free(th);
    return MakeError(tid);
  }

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), *tid);
  th->tlsvar = 1;  // Mark tstate as initialized
  std::unique_ptr<Thread> th_ptr(tstate);

  {
    rt::SpinGuard g(thread_map_lock_);
    if (unlikely(exited())) return MakeError(1);
    thread_map_[*tid] = tstate;
  }

  return th_ptr;
}

void Process::DoExit(int status) {
  // notify threads
  rt::SpinGuard g(thread_map_lock_);
  if (exited_) return;

  exited_ = true;
  xstate_ = status;
  barrier();
  for (const auto &[pid, th] : thread_map_) th->Kill();
  FutexTable::GetFutexTable().CleanupProcess(this);
}

pid_t usys_getpid() { return myproc().get_pid(); }

pid_t usys_gettid() { return mythread().get_tid(); }

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

long usys_clone3(struct clone_args *cl_args, size_t size) {
  long ret;
  if (unlikely(!cl_args->stack))
    ret = -EINVAL;
  else
    ret = DoClone(cl_args, cl_args->stack + cl_args->stack_size);

  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall(ret, "clone3", cl_args->flags,
               reinterpret_cast<void *>(cl_args->stack),
               reinterpret_cast<void *>(cl_args->stack),
               reinterpret_cast<void *>(cl_args->parent_tid),
               reinterpret_cast<void *>(cl_args->child_tid),
               reinterpret_cast<void *>(cl_args->tls));

  return ret;
}

long usys_clone(unsigned long clone_flags, unsigned long newsp,
                uintptr_t parent_tidptr, uintptr_t child_tidptr,
                unsigned long tls) {
  clone_args cl_args;
  cl_args.flags = clone_flags;
  cl_args.child_tid = child_tidptr;
  cl_args.parent_tid = parent_tidptr;
  cl_args.tls = tls;

  long ret = DoClone(&cl_args, newsp);
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall(ret, "clone", clone_flags, reinterpret_cast<void *>(newsp),
               reinterpret_cast<void *>(parent_tidptr),
               reinterpret_cast<void *>(child_tidptr),
               reinterpret_cast<void *>(tls));
  return ret;
}

void usys_exit(int status) {
  Thread *tptr = reinterpret_cast<Thread *>(thread_self()->junction_tstate_buf);
  tptr->set_xstate(status);
  tptr->~Thread();
  rt::Exit();
}

void usys_exit_group(int status) {
  // TODO(jfried): this must kill all other threads in this thread group...
  Thread *tptr = reinterpret_cast<Thread *>(thread_self()->junction_tstate_buf);
  myproc().DoExit(status);
  tptr->~Thread();
  rt::Exit();
}

}  // namespace junction
