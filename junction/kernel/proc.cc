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

inline constexpr uint64_t kThreadRequiredFlags =
    (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD | CLONE_SIGHAND);

inline constexpr uint64_t kVforkRequiredFlags = (CLONE_VM | CLONE_VFORK);

inline constexpr uint64_t kCheckFlags =
    (kThreadRequiredFlags | kVforkRequiredFlags);

namespace {

// Global allocation of PIDs
rt::Spin process_lock;
UIDGenerator<kMaxProcesses> pid_generator;
std::map<pid_t, unsigned long> pid_ref_count;
std::shared_ptr<Process> init_proc;

Status<pid_t> AllocPid(std::optional<pid_t> pgid = std::nullopt) {
  rt::SpinGuard guard(process_lock);
  std::optional<size_t> tmp = pid_generator();
  if (!tmp) return MakeError(ENOSPC);
  pid_ref_count[*tmp] = 1;
  if (pgid) pid_ref_count[*pgid] += 1;
  return *tmp;
}

void ReleasePid(pid_t pid, std::optional<pid_t> pgid = std::nullopt) {
  rt::SpinGuard guard(process_lock);

  if (--pid_ref_count[pid] == 0) {
    pid_generator.Release(pid);
    pid_ref_count.erase(pid);
  }

  if (pgid && --pid_ref_count[*pgid] == 0) {
    pid_generator.Release(*pgid);
    pid_ref_count.erase(*pgid);
  }
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
    tptr = (*forkp)->CreateThreadMain();
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
  if (cl_args->flags & CLONE_SETTLS) thread_set_fsbase(th, cl_args->tls);

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
  bool proc_done = proc_->ThreadFinish(this);
  if (tid_ != proc_->get_pid()) ReleasePid(tid_);
  if (proc_done) proc_->ProcessFinish();
}

void Process::ProcessFinish() {
  vfork_waker_.Wake();
  // Check if init has died
  if (unlikely(get_pid() == 1)) {
    syscall_exit(xstate_);
    std::unreachable();
  }

  // safe to access child_procs_ with no lock since the process is dead

  if (!child_procs_.size()) return;

  // reparent
  rt::SpinGuard g(init_proc->shared_sig_q_);
  for (auto &child : child_procs_) {
    rt::SpinGuard g(child->shared_sig_q_);
    child->parent_ = init_proc;
    init_proc->child_procs_.push_back(std::move(child));
  }
}

Process::~Process() { ReleasePid(pid_, pgid_); }

void Process::FinishExec(std::shared_ptr<MemoryMap> &&new_mm) {
  file_tbl_.DoCloseOnExec();
  mem_map_ = std::move(new_mm);
  vfork_waker_.Wake();
}

bool Process::ThreadFinish(Thread *th) {
  rt::SpinGuard g(thread_map_lock_);
  thread_map_.erase(th->get_tid());
  return thread_map_.size() == 0;
}

Status<std::shared_ptr<Process>> CreateInitProcess() {
  Status<pid_t> pid = AllocPid(1);
  if (!pid) return MakeError(pid);
  BUG_ON(*pid != 1);

  Status<std::shared_ptr<MemoryMap>> mm = CreateMemoryMap(kMemoryMappingSize);
  if (!mm) return MakeError(mm);

  const void *base = (*mm)->get_base();
  LOG(INFO) << "proc: Creating process with pid=" << *pid
            << ", mapping=" << base << "-"
            << reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base) +
                                        kMemoryMappingSize);
  return std::make_shared<Process>(*pid, std::move(*mm), *pid);
}

Status<std::shared_ptr<Process>> Process::CreateProcessVfork(
    rt::ThreadWaker &&w) {
  Status<pid_t> pid = AllocPid(get_pgid());
  if (!pid) return MakeError(pid);

  auto p = std::make_shared<Process>(*pid, mem_map_, file_tbl_, std::move(w),
                                     shared_from_this(), get_pgid());
  rt::SpinGuard g(shared_sig_q_);
  child_procs_.push_back(p);
  return p;
}

// Attach calling thread to this process; used for testing.
Thread &Process::CreateTestThread() {
  thread_t *th = thread_self();
  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), 1);
  th->tlsvar = static_cast<uint64_t>(ThreadState::kActive);
  thread_map_[1] = tstate;
  return *tstate;
}

Status<std::unique_ptr<Thread>> Process::CreateThreadMain() {
  thread_t *th = thread_create(nullptr, 0);
  if (!th) return MakeError(ENOMEM);

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), get_pid());
  th->tlsvar = static_cast<uint64_t>(ThreadState::kActive);
  thread_map_[get_pid()] = tstate;
  return std::unique_ptr<Thread>(tstate);
}

Status<std::unique_ptr<Thread>> Process::CreateThread() {
  thread_t *th = thread_create(nullptr, 0);
  if (unlikely(!th)) return MakeError(ENOMEM);

  Status<pid_t> tid = AllocPid();
  if (!tid) {
    thread_free(th);
    return MakeError(tid);
  }

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), *tid);
  th->tlsvar = static_cast<uint64_t>(ThreadState::kActive);
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

  xstate_ = status;
  store_release(&exited_, true);

  // Signal the parent and drop the reference to it
  siginfo_t sig;
  sig.si_signo = SIGCHLD;
  sig.si_pid = get_pid();
  sig.si_status = xstate_;
  sig.si_code = CLD_EXITED;

  {
    rt::SpinGuard g(shared_sig_q_);
    if (parent_) {
      parent_->Signal(sig);
      parent_.reset();
    }
  }

  for (const auto &[pid, th] : thread_map_) th->Kill();
  FutexTable::GetFutexTable().CleanupProcess(this);
}

pid_t usys_getpid() { return myproc().get_pid(); }

pid_t usys_gettid() { return mythread().get_tid(); }

int usys_arch_prctl(int code, unsigned long addr) {
  if (code != ARCH_SET_FS) return -EINVAL;
  thread_set_fsbase(thread_self(), addr);
  return 0;
}

pid_t usys_set_tid_address(int *tidptr) {
  Thread &tstate = mythread();
  tstate.set_child_tid(reinterpret_cast<uint32_t *>(tidptr));
  return tstate.get_tid();
}

long usys_vfork() {
  clone_args cl_args;
  memset(&cl_args, 0, sizeof(cl_args));

  cl_args.flags = kVforkRequiredFlags;

  long ret = DoClone(&cl_args, thread_self()->junction_tf.rsp);
  if (unlikely(GetCfg().strace_enabled())) LogSyscall(ret, "vfork");

  return ret;
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
  memset(&cl_args, 0, sizeof(cl_args));

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

extern "C" [[noreturn]] void usys_exit_finish(int status) {
  Thread *tptr = &mythread();
  tptr->set_xstate(status);
  tptr->~Thread();
  rt::Exit();
}

void usys_exit(int status) {
  if (IsOnStack(GetSyscallStack())) usys_exit_finish(status);

  __nosave_switch(reinterpret_cast<thread_fn_t>(usys_exit_finish),
                  GetSyscallStackBottom(), status);
}

void usys_exit_group(int status) {
  // TODO(jfried): this must kill all other threads in this thread group...
  myproc().DoExit(status);

  usys_exit(status);
}

}  // namespace junction
