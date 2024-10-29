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

// Global allocation of PIDs
rt::Spin process_lock;
UIDGenerator<kMaxProcesses> pid_generator;
std::map<pid_t, unsigned long> pid_ref_count;
std::shared_ptr<Process> init_proc;

void DecRefCountPid(pid_t pid) {
  assert(process_lock.IsHeld());
  if (--pid_ref_count[pid] == 0) {
    pid_generator.Release(pid);
    pid_ref_count.erase(pid);
  }
}

void IncRefCountPid(pid_t pid, int incr = 1) {
  assert(process_lock.IsHeld());
  pid_ref_count[pid] += incr;
}

Status<pid_t> AllocPid(std::optional<pid_t> pgid = std::nullopt,
                       std::optional<pid_t> sid = std::nullopt) {
  rt::SpinGuard guard(process_lock);
  std::optional<size_t> tmp = pid_generator();
  if (!tmp) return MakeError(ENOSPC);
  pid_ref_count[*tmp] = 1;
  if (pgid) IncRefCountPid(*pgid);
  if (sid) IncRefCountPid(*sid);
  return *tmp;
}

Status<pid_t> AllocNewSession() {
  rt::SpinGuard guard(process_lock);
  std::optional<size_t> tmp = pid_generator();
  if (!tmp) return MakeError(ENOSPC);
  pid_ref_count[*tmp] = 3;
  return *tmp;
}

void ReleasePid(pid_t pid, std::optional<pid_t> pgid = std::nullopt,
                std::optional<pid_t> sid = std::nullopt) {
  rt::SpinGuard guard(process_lock);
  DecRefCountPid(pid);
  if (pgid) DecRefCountPid(*pgid);
  if (sid) DecRefCountPid(*sid);
}

void AcquirePid(pid_t pid, std::optional<pid_t> pgid,
                std::optional<pid_t> sid) {
  rt::SpinGuard guard(process_lock);
  pid_generator.Acquire(pid);
  IncRefCountPid(pid);
  if (pgid) IncRefCountPid(*pgid);
  if (sid) IncRefCountPid(*sid);
}

void SetInitProc(std::shared_ptr<Process> proc) {
  assert(!init_proc);
  init_proc = std::move(proc);
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

  Status<Thread *> tptr;

  Thread &oldth = mythread();

  if (do_vfork) {
    rt::ThreadWaker waker;
    waker.Arm();
    Status<std::shared_ptr<Process>> forkp =
        oldth.get_process().CreateProcessVfork(std::move(waker));
    if (!forkp) return MakeCError(forkp);
    tptr = (*forkp)->CreateThreadMain(oldth.get_creds());
  } else {
    tptr = oldth.get_process().CreateThread(oldth.get_creds());
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

  if (do_vfork) {
    bool was_stopped = myproc().is_stopped();
    if (likely(!was_stopped)) {
      myproc().JobControlStop();
      myproc().WaitForFullStop();
    }
    if (unlikely(GetCfg().strace_enabled()))
      LogSyscall(newth.get_tid(), "vfork", &usys_vfork);
    {
      rt::Preempt::Lock();
      newth.ThreadReady();
      rt::Preempt::UnlockAndPark();
    }
    // Wait for child thread to exit or exec.
    if (!was_stopped) myproc().JobControlContinue();
  } else {
    newth.ThreadReady();
  }

  return newth.get_tid();
}

void Thread::DestroyThread(Thread *th) {
  assert(th->cold().ref_count_ == 0);
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
  if (tid_ != proc_->get_pid()) ReleasePid(tid_);
  if (proc_done) proc_->ProcessFinish();
  DestroyCold();
}

bool Thread::IsStopped() const { return proc_->is_stopped(); }

Status<void> Thread::DropUnusedStack() {
  return {};
  assert(get_process().is_fully_stopped());
  // If the thread has indicated that signals cannot be delivered on it then we
  // shouldn't assume that we can clobber above rsp.
  if (get_sighand().has_altstack()) return {};

  // Check if the rsp is on a known stack.
  uint64_t rsp = GetTrapframe().GetRsp();
  MemoryMap &mm = get_process().get_mem_map();
  std::optional<void *> top = mm.GetStackTop(rsp);
  if (!top) return {};

  // Check if the syscall is performed on top of the rsp.
  uint64_t resume_rsp = GetCaladanThread()->tf.rsp;
  std::optional<void *> resume_top = mm.GetStackTop(resume_rsp);
  if (resume_top && *resume_top == *top) rsp = resume_rsp;

  // Drop pages above the redzone.
  rsp = PageAlignDown(rsp - kRedzoneSize);
  uint64_t len = rsp - reinterpret_cast<uintptr_t>(*top);
  return KernelMAdvise(*top, len, MADV_DONTNEED);
}

Status<pid_t> Process::BecomeSessionLeader() {
  rt::SpinGuard g(process_lock);
  if (is_process_group_leader()) return MakeError(EPERM);
  IncRefCountPid(pid_, 2);
  DecRefCountPid(sid_);
  DecRefCountPid(pgid_);
  sid_ = pid_;
  pgid_ = pid_;
  return pid_;
}

Status<void> Process::JoinProcessGroup(pid_t pgid) {
  assert(pgid > 0);
  rt::SpinGuard g(process_lock);
  if (is_process_group_leader()) return MakeError(EPERM);
  DecRefCountPid(pgid_);
  IncRefCountPid(pgid);
  pgid_ = pgid;
  return {};
}

void Process::ProcessFinish() {
  if (unlikely(!mem_map_->DumpTracerReport())) {
    LOG(ERR) << "Failed to dump memory trace";
    syscall_exit(-1);
  }
  // Check if init has died
  if (unlikely(init_proc.get() == this)) {
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
  rt::SpinGuard g(init_proc->shared_sig_q_);
  for (auto &child : child_procs_) {
    rt::SpinGuard g(child->shared_sig_q_);
    child->parent_ = init_proc;
    init_proc->child_procs_.push_back(std::move(child));
  }
}

rt::Spin Process::pid_map_lock_;
std::map<pid_t, Process *> Process::pid_to_proc_;
Process::~Process() {
  DeregisterProcess(*this);
  ReleasePid(pid_, pgid_, sid_);
}

Status<void> Process::WaitForFullStop() {
  bool this_thread_stopped = IsJunctionThread() && this == &myproc();
  rt::SpinGuard g(child_thread_lock_);
  if (this_thread_stopped) stopped_count_ += 1;
  rt::Wait(child_thread_lock_, stopped_threads_,
           [&]() { return stopped_count_ == thread_map_.size() || exited_; });
  if (this_thread_stopped) stopped_count_ -= 1;
  if (exited_) return MakeError(ESRCH);
  return {};
}

Status<void> Process::WaitForNthStop(size_t stopcount) {
  rt::SpinGuard g(child_thread_lock_);
  rt::Wait(child_thread_lock_, stopped_threads_,
           [&]() { return stop_cnt_ >= stopcount || exited_; });
  if (exited_) return MakeError(ESRCH);
  return {};
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
  if (is_stopped() && stopped_count_ == remaining_threads)
    NotifyParentWait(kWaitableStopped);
  return remaining_threads == 0;
}

Status<std::shared_ptr<Process>> CreateInitProcess() {
  Status<pid_t> pid = AllocNewSession();
  if (!pid) return MakeError(pid);

  Status<std::shared_ptr<MemoryMap>> mm = CreateMemoryMap(kMemoryMappingSize);
  if (!mm) return MakeError(mm);

  return std::make_shared<Process>(*pid, std::move(*mm));
}

Status<std::shared_ptr<Process>> Process::CreateProcessVfork(
    rt::ThreadWaker &&w) {
  Status<pid_t> pid = AllocPid(get_pgid(), get_sid());
  if (!pid) return MakeError(pid);

  auto p = std::make_shared<Process>(*pid, mem_map_, file_tbl_, std::move(w),
                                     shared_from_this(), get_pgid(), get_fs(),
                                     get_sid());
  rt::SpinGuard g(shared_sig_q_);
  child_procs_.push_back(p);
  return p;
}

// Attach calling thread to this process; used for testing.
Thread &Process::CreateTestThread() {
  thread_t *th = thread_self();
  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  Credential cred;
  new (tstate) Thread(shared_from_this(), 1, cred);
  th->junction_thread = true;
  thread_map_[1] = tstate;
  return *tstate;
}

Status<Thread *> Process::CreateThreadMain(const Credential &cred) {
  thread_t *th = thread_create(nullptr, 0);
  if (!th) return MakeError(ENOMEM);

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  new (tstate) Thread(shared_from_this(), get_pid(), cred);
  th->junction_thread = true;
  thread_map_[get_pid()] = tstate;
  return tstate;
}

Status<Thread *> Process::CreateThread(const Credential &cred) {
  thread_t *th = thread_create(nullptr, 0);
  if (unlikely(!th)) return MakeError(ENOMEM);

  Status<pid_t> tid = AllocPid();
  if (!tid) {
    thread_free(th);
    return MakeError(tid);
  }

  Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);

  {
    rt::UniqueLock g(child_thread_lock_);
    if (unlikely(exited())) {
      g.Unlock();
      ReleasePid(*tid);
      thread_free(th);
      return MakeError(1);
    }
    new (tstate) Thread(shared_from_this(), *tid, cred);
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

void Process::KillThreadsAndWait() {
  bool in_proc = IsJunctionThread() && this == &myproc();
  rt::SpinGuard g(child_thread_lock_);

  // Kill any threads besides this one.
  for (const auto &[pid, th] : thread_map_)
    if (!in_proc || pid != mythread().get_tid()) th->Kill();

  size_t wait_for = in_proc ? 1 : 0;
  // Wait for other threads to exit.
  rt::Wait(child_thread_lock_, exec_waker_,
           [&] { return thread_map_.size() == wait_for; });
}

void Process::DoExit(int status) {
  // notify threads
  {
    rt::SpinGuard g(child_thread_lock_);
    if (exited_ || exec_waker_) return;

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

  if (is_session_leader()) {
    /* send sighup to procs in the foreground process group */
  }
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

void Process::ThreadStopWait() {
  rt::SpinGuard g(child_thread_lock_);
  if (!is_stopped()) return;

  if (++stopped_count_ == thread_map_.size()) {
    NotifyParentWait(kWaitableStopped);

    // Also notify waiters that all threads have stopped
    stopped_threads_.WakeAll();
  }

  rt::Wait(child_thread_lock_, stopped_threads_,
           [&]() { return !is_stopped() || exited_; });
  stopped_count_--;
}

void Thread::StopWait(int rax) {
  // Flag should be set on entry.
  assert(rt::GetInterruptibleStatus(GetCaladanThread()) !=
         rt::InterruptibleStatus::kNone);
  assert(!check_prepared(GetCaladanThread()));
  assert(in_kernel());
  cold().stopped_rax_ = rax;
  myproc().ThreadStopWait();
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

long usys_getppid() { return myproc().get_ppid(); }

long usys_getpid() { return myproc().get_pid(); }

long usys_gettid() { return mythread().get_tid(); }

long usys_getpgrp() { return myproc().get_pgid(); }

long usys_setpgid(pid_t pid, pid_t pgid) {
  // TODO: check that pgid is a valid process group and that pgid's sid matches.
  Status<void> ret;

  if (pgid == 0) pgid = myproc().get_pgid();

  if (pid == 0 || pid == myproc().get_pid()) {
    ret = myproc().JoinProcessGroup(pgid);
  } else {
    std::shared_ptr<Process> proc = Process::Find(pid);
    if (!proc) return -ESRCH;
    ret = proc->JoinProcessGroup(pgid);
  }

  if (unlikely(ret)) return MakeCError(ret);
  return 0;
}

long usys_getpgid(pid_t pid) {
  if (pid == 0 || pid == myproc().get_pid()) return myproc().get_pgid();
  std::shared_ptr<Process> proc = Process::Find(pid);
  if (!proc) return -ESRCH;
  return proc->get_pgid();
}

long usys_getsid(pid_t pid) {
  if (pid == 0 || pid == myproc().get_pid()) return myproc().get_sid();
  std::shared_ptr<Process> proc = Process::Find(pid);
  if (!proc) return -ESRCH;
  return proc->get_sid();
}

long usys_setsid() {
  Process &p = myproc();
  if (p.is_session_leader()) return 0;
  if (p.is_process_group_leader()) return -EPERM;
  Status<pid_t> ret = p.BecomeSessionLeader();
  if (unlikely(!ret)) return MakeCError(ret);
  return *ret;
}

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

  long ret = DoClone(&cl_args, mythread().GetSyscallFrame().GetRsp());
  if (unlikely(GetCfg().strace_enabled() && ret < 0))
    LogSyscall(ret, "vfork", &usys_vfork);

  return ret;
}

long usys_clone3(struct clone_args *cl_args, size_t size) {
  long ret;
  if (unlikely(!cl_args->stack))
    ret = -EINVAL;
  else
    ret = DoClone(cl_args, cl_args->stack + cl_args->stack_size);

  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall(ret, "clone3", &usys_clone,
               static_cast<strace::CloneFlag>(cl_args->flags),
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

  if (!newsp) newsp = mythread().GetSyscallFrame().GetRsp();

  cl_args.flags = clone_flags;
  cl_args.child_tid = child_tidptr;
  cl_args.parent_tid = parent_tidptr;
  cl_args.tls = tls;

  long ret = DoClone(&cl_args, newsp);
  if (unlikely(GetCfg().strace_enabled())) {
    LogSyscall(
        ret, "clone", &usys_clone, static_cast<strace::CloneFlag>(clone_flags),
        reinterpret_cast<void *>(newsp),
        reinterpret_cast<void *>(parent_tidptr),
        reinterpret_cast<void *>(child_tidptr), reinterpret_cast<void *>(tls));
  }
  return ret;
}

[[noreturn]] void FinishExit(int status) {
  Thread *tptr = &mythread();
  tptr->set_xstate(status);
  rt::Preempt::Lock();
  if (--tptr->cold().ref_count_ <= 0) {
    assert(tptr->cold().ref_count_ == 0);
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

[[noreturn]] void usys_exit(int status) {
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall("exit", &usys_exit, status);
  FinishExit(status);
}

void usys_exit_group(int status) {
  if (unlikely(GetCfg().strace_enabled()))
    LogSyscall("exit_group", &usys_exit_group, status);
  myproc().DoExit(status);
  FinishExit(status);
}

}  // namespace junction
