extern "C" {
#include <asm/prctl.h>
#include <linux/futex.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib/caladan/runtime/defs.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/sched.h>
}

#include <cstdlib>
#include <cstring>

#include "junction/base/arch.h"
#include "junction/base/bits.h"
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
#include "junction/snapshot/snapshot.h"
#include "junction/syscall/entry.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"

namespace junction {

inline constexpr uint64_t kThreadRequiredFlags =
    (CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_THREAD | CLONE_SIGHAND);

inline constexpr uint64_t kVforkRequiredFlags = (CLONE_VM | CLONE_VFORK);

inline constexpr uint64_t kCheckFlags =
    (kThreadRequiredFlags | kVforkRequiredFlags);

namespace detail {

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

// should only be called on restore path, no multithreading
void AcquirePid(pid_t pid) {
  pid_generator.Acquire(pid);
  pid_ref_count[pid] += 1;
}

// should only be called on restore path
void SetInitProc(std::shared_ptr<Process> proc) { detail::init_proc = proc; }

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

  Status<Thread *> tptr;

  Thread &oldth = mythread();

  if (do_vfork) {
    rt::ThreadWaker waker;
    waker.Arm();
    Status<std::shared_ptr<Process>> forkp =
        oldth.get_process().CreateProcessVfork(std::move(waker));
    if (!forkp) return MakeCError(forkp);
    tptr = (*forkp)->CreateThreadMain();
  } else {
    tptr = oldth.get_process().CreateThread();
  }

  if (!tptr) return MakeCError(tptr);

  Thread &newth = **tptr;
  thread_t &new_cth = *newth.GetCaladanThread();
  thread_t &old_cth = *oldth.GetCaladanThread();

  // Clone the trap frame
  uint64_t sys_rsp = newth.get_syscall_stack_rsp();
  SyscallFrame &restore_tf = oldth.GetSyscallFrame().CloneTo(&sys_rsp);
  restore_tf.SetRax(0, rsp);
  newth.mark_enter_kernel();
  restore_tf.MakeUnwinderSysret(newth, new_cth.tf);

  // Set FSBASE if requested.
  if (cl_args->flags & CLONE_SETTLS) {
    thread_set_fsbase(&new_cth, cl_args->tls);
  } else {
    new_cth.has_fsbase = old_cth.has_fsbase;
    new_cth.tf.fsbase = old_cth.tf.fsbase;
  }

  // Write this thread's tid into the requested location.
  if (cl_args->flags & CLONE_PARENT_SETTID)
    *reinterpret_cast<uint32_t *>(cl_args->parent_tid) = newth.get_tid();

  // Save a pointer to the child_tid address if requested, so it can later
  // notify the parent of the child's exit via futex.
  if (cl_args->flags & CLONE_CHILD_CLEARTID)
    newth.set_child_tid(reinterpret_cast<uint32_t *>(cl_args->child_tid));

  newth.ThreadReady();

  // Wait for child thread to exit or exec.
  if (do_vfork) {
    if (unlikely(GetCfg().strace_enabled()))
      LogSyscall(newth.get_tid(), "vfork", &usys_vfork);
    rt::WaitForever();
  }

  return newth.get_tid();
}

}  // namespace detail

void Thread::DestroyThread(Thread *th) {
  assert(th->ref_count_ == 0);
  thread_t *cth = th->GetCaladanThread();
  assert(cth != thread_self());
  th->~Thread();
  // Ensure the thread is no longer scheduled.
  if (unlikely(load_acquire(&cth->thread_running))) {
    /* wait until the scheduler finishes switching stacks */
    while (load_acquire(&cth->thread_running)) cpu_relax();
  }
  thread_free(cth);
}

Thread::~Thread() {
  uint32_t *child_tid = get_child_tid();
  if (child_tid) {
    *child_tid = 0;
    FutexTable::GetFutexTable().Wake(child_tid);
  }
  bool proc_done = proc_->ThreadFinish(this);
  if (tid_ != proc_->get_pid()) detail::ReleasePid(tid_);
  if (proc_done) proc_->ProcessFinish();
}

bool Thread::IsStopped() const { return proc_->is_stopped(); }

void Process::ProcessFinish() {
  // Check if init has died
  if (unlikely(get_pid() == 1)) {
    syscall_exit(xstate_);
    std::unreachable();
  }

  // Close all file descriptors since ftbl destructor is not called until
  // process is reaped, but a parent might be blocked on the other end of a
  // pipe.
  get_file_table().Destroy();

  // safe to access child_procs_ with no lock since the process is dead

  if (!child_procs_.size()) return;

  // reparent
  rt::SpinGuard g(detail::init_proc->shared_sig_q_);
  for (auto &child : child_procs_) {
    rt::SpinGuard g(child->shared_sig_q_);
    child->parent_ = detail::init_proc;
    detail::init_proc->child_procs_.push_back(std::move(child));
  }
}

rt::Spin Process::pid_map_lock_;
std::map<pid_t, Process *> Process::pid_to_proc_;
Process::~Process() {
  DeregisterProcess(*this);
  detail::ReleasePid(pid_, pgid_);
}

void Process::FinishExec(std::shared_ptr<MemoryMap> &&new_mm) {
  {
    rt::SpinGuard g(child_thread_lock_);

    // Kill any threads besides this one.
    for (const auto &[pid, th] : thread_map_)
      if (pid != mythread().get_tid()) th->Kill();

    // Wait for other threads to exit.
    rt::Wait(child_thread_lock_, exec_waker_,
             [this] { return thread_map_.size() == 1; });
  }

  file_tbl_.DoCloseOnExec();
  mem_map_ = std::move(new_mm);
  vfork_waker_.Wake();
}

bool Process::ThreadFinish(Thread *th) {
  rt::SpinGuard g(child_thread_lock_);
  accumulated_runtime_ += th->GetRuntime();
  thread_map_.erase(th->get_tid());
  size_t remaining_threads = thread_map_.size();
  if (remaining_threads == 1) exec_waker_.Wake();
  if (stopped_ && stopped_count_ == remaining_threads)
    NotifyParentWait(kWaitableStopped);
  return remaining_threads == 0;
}

Status<std::shared_ptr<Process>> CreateInitProcess() {
  Status<pid_t> pid = detail::AllocPid(1);
  if (!pid) return MakeError(pid);
  BUG_ON(*pid != 1);

  Status<std::shared_ptr<MemoryMap>> mm = CreateMemoryMap(kMemoryMappingSize);
  if (!mm) return MakeError(mm);

  detail::init_proc = std::make_shared<Process>(*pid, std::move(*mm), *pid);
  return detail::init_proc;
}

Status<std::shared_ptr<Process>> Process::CreateProcessVfork(
    rt::ThreadWaker &&w) {
  Status<pid_t> pid = detail::AllocPid(get_pgid());
  if (!pid) return MakeError(pid);

  auto p = std::make_shared<Process>(*pid, mem_map_, file_tbl_, std::move(w),
                                     shared_from_this(), get_pgid(), get_fs());
  rt::SpinGuard g(shared_sig_q_);
  child_procs_.push_back(p);
  return p;
}

// Attach calling thread to this process; used for testing.
Thread &Process::CreateTestThread() {
  thread_t *th = thread_self();
  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), 1);
  th->junction_thread = true;
  thread_map_[1] = tstate;
  return *tstate;
}

Status<Thread *> Process::CreateThreadMain() {
  thread_t *th = thread_create(nullptr, 0);
  if (!th) return MakeError(ENOMEM);

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), get_pid());
  th->junction_thread = true;
  thread_map_[get_pid()] = tstate;
  return tstate;
}

Status<Thread *> Process::CreateThread() {
  thread_t *th = thread_create(nullptr, 0);
  if (unlikely(!th)) return MakeError(ENOMEM);

  Status<pid_t> tid = detail::AllocPid();
  if (!tid) {
    thread_free(th);
    return MakeError(tid);
  }

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);

  {
    rt::UniqueLock g(child_thread_lock_);
    if (unlikely(exited())) {
      g.Unlock();
      detail::ReleasePid(*tid);
      thread_free(th);
      return MakeError(1);
    }
    new (tstate) Thread(shared_from_this(), *tid);
    th->junction_thread = true;
    thread_map_[*tid] = tstate;
  }

  return tstate;
}

int WaitStateToSi(unsigned int state) {
  switch (state) {
      // TODO: differentiate killed and exited
    case kWaitableExited:
      return CLD_EXITED;
    case kWaitableStopped:
      return CLD_STOPPED;
    case kWaitableContinued:
      return CLD_CONTINUED;
    default:
      BUG();
  }
}

void Process::FillWaitInfo(siginfo_t &info) const {
  info.si_signo = SIGCHLD;
  info.si_pid = get_pid();
  info.si_status = wait_status_;
  info.si_code = WaitStateToSi(wait_state_);
  info.si_uid = 0;
}

int Process::GetWaitStatus() const {
  switch (wait_state_) {
    case kWaitableExited:
      return __W_EXITCODE(wait_status_, 0);
    case kWaitableStopped:
      return __W_STOPCODE(SIGSTOP);
    case kWaitableContinued:
      return __W_CONTINUED;
    default:
      BUG();
  }
}

void Process::ReapChild(Process *child) {
  assert(shared_sig_q_.IsHeld());

  if (child->wait_state_ != kWaitableExited) {
    child->wait_state_ = kNotWaitable;
    return;
  }

  child->parent_.reset();
  std::erase_if(child_procs_, [child](std::shared_ptr<Process> &p) {
    return p.get() == child;
  });
}

void Process::NotifyParentWait(unsigned int state, int status) {
  if (!parent_) return;

  rt::UniqueLock<rt::Spin> lock(parent_->shared_sig_q_);
  wait_status_ = status;
  wait_state_ = state;

  siginfo_t sig;
  FillWaitInfo(sig);
  // forward signal
  parent_->SignalLocked(std::move(lock), sig);
}

void Process::DoExit(int status) {
  // notify threads
  {
    rt::SpinGuard g(child_thread_lock_);
    if (exited_) return;

    xstate_ = status;
    store_release(&exited_, true);
    stopped_threads_.WakeAll();

    // Kill any threads besides this one.
    for (const auto &[pid, th] : thread_map_)
      if (pid != mythread().get_tid()) th->Kill();

    // Wait for other threads to exit.
    rt::Wait(child_thread_lock_, exec_waker_,
             [this] { return thread_map_.size() == 1; });
  }

  if (status != 0)
    LOG(INFO) << "proc: pid " << get_pid() << " exiting with code " << status;

  vfork_waker_.Wake();
  NotifyParentWait(kWaitableExited, status);
}

Status<Process *> Process::FindWaitableProcess(idtype_t idtype, id_t id,
                                               unsigned int wait_flags) {
  assert(shared_sig_q_.IsHeld());

#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 36)
  if (idtype == P_PIDFD) return MakeError(EINVAL);
#endif
  if (idtype == P_PGID && id == 0) id = get_pgid();

  bool has_candidates = false;

  for (auto &p : child_procs_) {
    // Check filter conditions
    if (idtype == P_PID && p->get_pid() != static_cast<pid_t>(id)) continue;
    if (idtype == P_PGID && p->get_pgid() != static_cast<pid_t>(id)) continue;

    has_candidates = true;
    if (p->get_wait_state() & wait_flags) return p.get();
  }

  if (!has_candidates) return MakeError(ECHILD);
  return nullptr;
}

Status<pid_t> Process::DoWait(idtype_t idtype, id_t id, int options,
                              siginfo_t *infop, int *wstatus) {
  unsigned int wait_state_flags = WEXITED;
  wait_state_flags |= options & (WCONTINUED | WSTOPPED);

  bool nonblocking = options & WNOHANG;
  bool dont_reap = options & WNOWAIT;

  Status<Process *> tmp;

  rt::SpinGuard g(shared_sig_q_);

  if (!nonblocking) {
    WaitInterruptible(shared_sig_q_, child_waiters_, [&, this] {
      tmp = FindWaitableProcess(idtype, id, wait_state_flags);
      return !tmp || *tmp;
    });

    // check one more time, we may have been woken by a SIGCHLD
    if (!tmp || !*tmp) tmp = FindWaitableProcess(idtype, id, wait_state_flags);
    if (!tmp) return MakeError(tmp);
    if (!*tmp) return MakeError(ERESTARTSYS);
  } else {
    tmp = FindWaitableProcess(idtype, id, wait_state_flags);
    if (!tmp) return MakeError(tmp);
    if (!*tmp) return MakeError(EAGAIN);
  }

  Process *p = *tmp;
  if (infop) p->FillWaitInfo(*infop);
  if (wstatus) *wstatus = p->GetWaitStatus();
  pid_t pid = p->get_pid();
  if (!dont_reap) ReapChild(p);
  return pid;
}

std::pair<idtype_t, id_t> PidtoId(pid_t pid) {
  if (pid < -1) return {P_PGID, -pid};
  if (pid == -1) return {P_ALL, 0};
  if (pid == 0) return {P_PGID, 0};
  return {P_PID, pid};
}

void Process::ThreadStopWait(Thread &th) {
  // Flag should be set on entry.
  assert(rt::GetInterruptibleStatus(th.GetCaladanThread()) !=
         rt::InterruptibleStatus::kNone);
  assert(!check_prepared(th.GetCaladanThread()));
  assert(th.in_kernel());

  rt::SpinGuard g(child_thread_lock_);
  if (!stopped_) return;

  if (++stopped_count_ == thread_map_.size()) {
    NotifyParentWait(kWaitableStopped);

    // Also notify waiters that all threads have stopped
    stopped_threads_.WakeAll();
  }

  rt::Wait(child_thread_lock_, stopped_threads_,
           [&]() { return !stopped_ || exited_; });
  stopped_count_--;
}

long usys_wait4(pid_t pid, int *wstatus, int options, struct rusage *ru) {
  const auto &[idtype, id] = PidtoId(pid);
  Status<pid_t> ret = myproc().DoWait(idtype, id, options, nullptr, wstatus);
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_waitid(int which, pid_t pid, siginfo_t *infop, int options,
                 struct rusage *ru) {
  Status<pid_t> ret = myproc().DoWait(static_cast<idtype_t>(which), pid,
                                      options, infop, nullptr);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_getpid() { return myproc().get_pid(); }

long usys_gettid() { return mythread().get_tid(); }

long usys_arch_prctl(int code, unsigned long addr) {
  // TODO: supporting Intel AMX requires requesting the feature from the kernel.
  if (code != ARCH_SET_FS) return -EINVAL;
  thread_set_fsbase(thread_self(), addr);
  return 0;
}

long usys_set_tid_address(int *tidptr) {
  Thread &tstate = mythread();
  tstate.set_child_tid(reinterpret_cast<uint32_t *>(tidptr));
  return tstate.get_tid();
}

long usys_vfork() {
  clone_args cl_args;
  memset(&cl_args, 0, sizeof(cl_args));

  cl_args.flags = kVforkRequiredFlags;

  long ret = detail::DoClone(&cl_args, mythread().GetSyscallFrame().GetRsp());
  if (unlikely(GetCfg().strace_enabled() && ret < 0))
    LogSyscall(ret, "vfork", &usys_vfork);

  return ret;
}

long usys_clone3(struct clone_args *cl_args, size_t size) {
  long ret;
  if (unlikely(!cl_args->stack))
    ret = -EINVAL;
  else
    ret = detail::DoClone(cl_args, cl_args->stack + cl_args->stack_size);

  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall(ret, "clone3", &usys_clone, cl_args->flags,
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

  long ret = detail::DoClone(&cl_args, newsp);
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall(
        ret, "clone", &usys_clone, clone_flags, reinterpret_cast<void *>(newsp),
        reinterpret_cast<void *>(parent_tidptr),
        reinterpret_cast<void *>(child_tidptr), reinterpret_cast<void *>(tls));
  return ret;
}

[[noreturn]] void usys_exit(int status) {
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall("exit", &usys_exit, status);
  Thread *tptr = &mythread();
  tptr->set_xstate(status);
  rt::Preempt::Lock();
  if (--tptr->ref_count_ <= 0) {
    assert(tptr->ref_count_ == 0);
    rt::Preempt::Unlock();
    RunOnSyscallStack([tptr]() {
      tptr->~Thread();
      rt::Exit();
    });
  }

  // A reference holder will clean up this thread.
  rt::Preempt::UnlockAndPark();
  std::unreachable();
}

void usys_exit_group(int status) {
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall("exit_group", &usys_exit_group, status);
  myproc().DoExit(status);
  usys_exit(status);
}

}  // namespace junction
