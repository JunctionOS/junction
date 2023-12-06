// proc.h - metadata for procs and threads

#pragma once

extern "C" {
#include <signal.h>
#include <sys/resource.h>
#include <sys/uio.h>

#include "lib/caladan/runtime/defs.h"
}

#include <span>
#include <string>
#include <vector>

#include "junction/base/error.h"
#include "junction/base/time.h"
#include "junction/bindings/net.h"
#include "junction/kernel/sigframe.h"
#include "junction/snapshot/file.h"
#include "junction/snapshot/mm.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {
Status<siginfo_t> SiginfoFromBytes(std::span<const std::byte> serialized) {
  if (serialized.size() != sizeof(siginfo_t)) {
    return MakeError(EINVAL);
  }

  siginfo_t s;
  memcpy(&s, serialized.data(), sizeof(siginfo_t));
  return s;
}

void SiginfoSerialize(Snapshotter &s, siginfo_t const &sig) {
  s.MetadataPush(
      {reinterpret_cast<std::byte const *>(&sig), sizeof(siginfo_t)});
}
}  // namespace

class ThreadMetadata {
 public:
  void Serialize(Snapshotter &s) const & {
    constant_.Serialize(s);
    variable_.Serialize(s);
  }
  size_t SerializedSize() const & {
    return constant_.SerializedSize() + variable_.SerializedSize();
  }

  void SetThreadId(pid_t tid) { constant_.SetThreadId(tid); }
  void SetChildThreadId(uint32_t *child_tid) {
    constant_.SetChildThreadId(child_tid);
  }
  void SetInSyscall(bool in_syscall) { constant_.SetInSyscall(in_syscall); }
  void SetExitState(int xstate) { constant_.SetExitState(xstate); }
  void SetCurrentSyscallFrame(void *cur_syscall_frame) {
    constant_.SetCurrentSyscallFrame(cur_syscall_frame);
  }
  void SetSignalHandlerBlocked(uint64_t blocked) {
    constant_.SetSignalHandlerBlocked(blocked);
  }
  void SetSignalHandlerSavedBlocked(uint64_t saved_blocked) {
    constant_.SetSignalHandlerSavedBlocked(saved_blocked);
  }
  void SetSignalHandlerAltStack(stack_t stack) {
    constant_.SetSignalHandlerAltStack(stack);
  }
  void SetSignalQueuePending(uint64_t pending) {
    constant_.SetSignalQueuePending(pending);
  }

  void ReserveNPendingSignals(size_t const n_signals) {
    constant_.ReserveNPendingSignals(n_signals);
    variable_.ReserveNPendingSignals(n_signals);
  }
  void AddPendingSignal(siginfo_t const &sig) {
    variable_.AddPendingSignal(sig);
  }

  Status<void> DeserializeConstant(std::span<const std::byte> serialized) {
    if (serialized.size() != sizeof(ConstantThreadMetadata)) {
      return MakeError(EINVAL);
    }
    memcpy(&this->constant_, serialized.data(), sizeof(ConstantThreadMetadata));
    return {};
  }
  Status<void> DeserializeVariable(std::span<const std::byte> serialized) {
    if (serialized.size() <
        this->constant_.pending_signals_sz_ * sizeof(siginfo_t)) {
      return MakeError(EINVAL);
    }
    this->variable_.ReserveNPendingSignals(this->constant_.pending_signals_sz_);
    for (size_t idx = 0; idx < this->constant_.pending_signals_sz_; idx++) {
      auto const &signal = SiginfoFromBytes(serialized.subspan(
          idx * sizeof(siginfo_t), (idx + 1) * sizeof(siginfo_t)));
      if (unlikely(!signal)) {
        return MakeError(signal);
      }
      this->variable_.pending_signals_.emplace_back(*signal);
    }
    return {};
  }
  static Status<ThreadMetadata> FromBytes(
      std::span<const std::byte> serialized) {
    ThreadMetadata pm;
    auto const &constant = pm.DeserializeConstant(
        serialized.subspan(0, sizeof(ConstantThreadMetadata)));
    if (unlikely(!constant)) {
      return MakeError(constant);
    }

    auto const &variable = pm.DeserializeVariable(
        serialized.subspan(sizeof(ConstantThreadMetadata),
                           serialized.size() - sizeof(ConstantThreadMetadata)));
    if (unlikely(!variable)) {
      return MakeError(variable);
    }

    return pm;
  }
  pid_t GetTid() const & { return constant_.GetTid(); };
  uint32_t *GetChildTid() const & { return constant_.GetChildTid(); }
  bool GetInSyscall() const & { return constant_.GetInSyscall(); }
  int GetXstate() const & { return constant_.GetXstate(); }
  k_sigframe *GetCurSyscallFrame() const & {
    return constant_.GetCurSyscallFrame();
  }
  uint64_t GetSignalHandlerBlocked() const & {
    return constant_.GetSignalHandlerBlocked();
  }
  std::optional<uint64_t> GetSignalHandlerSavedBlocked() const & {
    return constant_.GetSignalHandlerSavedBlocked();
  }
  stack_t GetSignalHandlerAltStack() const & {
    return constant_.GetSignalHandlerAltStack();
  }
  uint64_t GetSignalQueuePending() const & {
    return constant_.GetSignalQueuePending();
  }
  std::span<const siginfo_t> GetPendingSignals() const & {
    return variable_.GetPendingSignals();
  }

 private:
#pragma pack(push, 1)
  class ConstantThreadMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      s.MetadataPush(
          {reinterpret_cast<std::byte const *>(this), SerializedSize()});
    }
    size_t SerializedSize() const & { return sizeof(ConstantThreadMetadata); }
    void SetThreadId(pid_t tid) { tid_ = tid; }
    void SetChildThreadId(uint32_t *child_tid) {
      child_tid_ = reinterpret_cast<uintptr_t>(child_tid);
    }
    void SetInSyscall(bool in_syscall) { in_syscall_ = in_syscall; }
    void SetExitState(int xstate) { xstate_ = xstate; }
    void SetCurrentSyscallFrame(void *cur_syscall_frame) {
      cur_syscall_frame_ = reinterpret_cast<uintptr_t>(cur_syscall_frame);
    }

    void SetSignalHandlerBlocked(uint64_t blocked) {
      signal_handler_blocked_ = blocked;
    }
    void SetSignalHandlerSavedBlocked(uint64_t saved_blocked) {
      signal_handler_saved_blocked_ = saved_blocked;
      has_signal_handler_saved_blocked_ = true;
    }
    void SetSignalHandlerAltStack(stack_t stack) {
      signal_handler_altstack_sp_ = reinterpret_cast<uintptr_t>(stack.ss_sp);
      signal_handler_altstack_flags_ = stack.ss_flags;
      signal_handler_altstack_size_ = stack.ss_size;
    }
    void SetSignalQueuePending(uint64_t pending) {
      signal_queue_pending_ = pending;
    }

    void ReserveNPendingSignals(size_t const n_signals) {
      pending_signals_sz_ = n_signals;
    }

    pid_t GetTid() const & { return tid_; };
    uint32_t *GetChildTid() const & {
      return reinterpret_cast<uint32_t *>(child_tid_);
    }
    bool GetInSyscall() const & { return in_syscall_; }
    int GetXstate() const & { return xstate_; }
    k_sigframe *GetCurSyscallFrame() const & {
      return reinterpret_cast<k_sigframe *>(cur_syscall_frame_);
    }

    // thread signal handler
    uint64_t GetSignalHandlerBlocked() const & {
      return signal_handler_blocked_;
    }
    std::optional<uint64_t> GetSignalHandlerSavedBlocked() const & {
      if (has_signal_handler_saved_blocked_) {
        return signal_handler_saved_blocked_;
      }
      return {};
    }

    stack_t GetSignalHandlerAltStack() const & {
      return {
          .ss_sp = reinterpret_cast<void *>(signal_handler_altstack_sp_),
          .ss_flags = signal_handler_altstack_flags_,
          .ss_size = signal_handler_altstack_size_,
      };
    }

    uint64_t GetSignalQueuePending() const & { return signal_queue_pending_; }

   private:
    friend ThreadMetadata;
    pid_t tid_;
    uintptr_t child_tid_ = 0;
    bool in_syscall_;
    int xstate_;
    uintptr_t cur_syscall_frame_;

    // thread signal handler
    uint64_t signal_handler_blocked_;
    uint64_t signal_handler_saved_blocked_;
    bool has_signal_handler_saved_blocked_{false};
    uintptr_t signal_handler_altstack_sp_;
    int signal_handler_altstack_flags_;
    size_t signal_handler_altstack_size_;
    uint64_t signal_queue_pending_;
    size_t pending_signals_sz_;
  };
#pragma pack(pop)
  class VariableLengthThreadMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      for (auto const &sig : pending_signals_) {
        SiginfoSerialize(s, sig);
      }
    }
    size_t SerializedSize() const & {
      return sizeof(siginfo_t) * pending_signals_.size() /* pending_signals_ */
          ;
    }

    void ReserveNPendingSignals(size_t const n_signals) {
      pending_signals_.reserve(n_signals);
    }
    void AddPendingSignal(siginfo_t const &sig) {
      pending_signals_.push_back(sig);
    }
    std::span<const siginfo_t> GetPendingSignals() const & {
      return pending_signals_;
    }

   private:
    friend ThreadMetadata;
    std::vector<siginfo_t> pending_signals_;
  };

  ConstantThreadMetadata constant_;
  VariableLengthThreadMetadata variable_;
};

class ProcessMetadata {
 public:
  // serialization
  //
  void Serialize(Snapshotter &s) const & {
    constant_.Serialize(s);
    variable_.Serialize(s);
  }

  size_t SerializedSize() const & {
    return constant_.SerializedSize() + variable_.SerializedSize();
  }

  // constant
  void SetTrapframe(thread_tf const tf) { constant_.SetTrapframe(tf); }
  void SetProcId(pid_t const pid) { constant_.SetProcId(pid); }
  void SetProcGid(pid_t const pgid) { constant_.SetProcGid(pgid); }
  void SetProcExitState(int const xstate) {
    constant_.SetProcExitState(xstate);
  }
  void SetProcLimitNumberOfFiles(rlimit limit_nofile) {
    constant_.SetProcLimitNumberOfFiles(limit_nofile);
  }
  void SetMemoryMapLockIsHeld(bool is_held) {
    constant_.SetFileTableLockIsHeld(is_held);
  }
  void SetMemoryMapBreakAddr(uintptr_t brk_addr) {
    constant_.SetMemoryMapBreakAddr(brk_addr);
  }
  void SetMemoryMapBase(uintptr_t base) { constant_.SetMemoryMapBase(base); }
  void SetMemoryMapLen(uintptr_t len) { constant_.SetMemoryMapLen(len); }
  void SetITimerInterval(Duration interval) {
    constant_.SetITimerInterval(interval);
  }
  void SetITimerNextFire(Time next_fire) {
    constant_.SetITimerNextFire(next_fire);
  }
  void SetSignalQueuePending(uint64_t pending) {
    constant_.SetSignalQueuePending(pending);
  }
  void AddSignalTableEntry(size_t idx, k_sigaction const &sigaction) {
    constant_.AddSignalTableEntry(idx, sigaction);
  }

  // variable
  void SetBinaryPath(std::string const &binary_path) {
    constant_.SetBinaryPath(binary_path);
    variable_.SetBinaryPath(binary_path);
  }

  void ReserveNThreads(size_t const n_threads) {
    constant_.ReserveNThreads(n_threads);
    variable_.ReserveNThreads(n_threads);
  }
  void AddThread(ThreadMetadata const &thread) { variable_.AddThread(thread); }

  void ReserveNChildProcs(size_t const n_children) {
    constant_.ReserveNChildProcs(n_children);
    variable_.ReserveNChildProcs(n_children);
  }
  void AddChildProc(ProcessMetadata const *const m) {
    variable_.AddChildProc(m);
  }

  void ReserveNFiles(size_t const n_files) {
    constant_.ReserveNFiles(n_files);
    variable_.ReserveNFiles(n_files);
  }
  void AddFile(FileMetadata const &m) { variable_.AddFile(m); }

  void ReserveNVMAreas(size_t const n_vmas) {
    constant_.ReserveNVMAreas(n_vmas);
    variable_.ReserveNVMAreas(n_vmas);
  }
  void AddVMArea(VMAreaMetadata const &m) { variable_.AddVMArea(m); }

  void ReserveNPendingSignals(size_t const n_signals) {
    constant_.ReserveNPendingSignals(n_signals);
    variable_.ReserveNPendingSignals(n_signals);
  }
  void AddPendingSignal(siginfo_t const &sig) {
    variable_.AddPendingSignal(sig);
  }

  Status<void> DeserializeConstant(std::span<const std::byte> serialized) {
    if (serialized.size() != sizeof(ConstantProcessMetadata)) {
      return MakeError(EINVAL);
    }
    memcpy(&this->constant_, serialized.data(),
           sizeof(ConstantProcessMetadata));
    return {};
  }
  Status<void> DeserializeVariable(std::span<const std::byte> serialized) {
    this->variable_.ReserveNThreads(this->constant_.n_threads_);
    this->variable_.ReserveNFiles(this->constant_.n_files_);
    this->variable_.ReserveNVMAreas(this->constant_.n_vmareas_);
    this->variable_.ReserveNPendingSignals(this->constant_.n_pending_signals_);
    this->variable_.ReserveNChildProcs(this->constant_.n_child_procs_);

    size_t start_idx = 0;
    auto const &filename_buffer = serialized.subspan(
        start_idx, start_idx + this->constant_.binary_path_sz_);
    this->variable_.SetBinaryPath(
        std::string(reinterpret_cast<char const *>(filename_buffer.data()),
                    filename_buffer.size()));
    start_idx += this->constant_.binary_path_sz_;

    for (size_t idx = 0; idx < this->constant_.n_threads_; idx++) {
      auto const &thread =
          ThreadMetadata::FromBytes(serialized.subspan(start_idx));
      if (unlikely(!thread)) {
        return MakeError(thread);
      }
      start_idx += thread->SerializedSize();
      this->variable_.threads_.emplace_back(*thread);
    }
    for (size_t idx = 0; idx < this->constant_.n_files_; idx++) {
      auto const &file = FileMetadata::FromBytes(serialized.subspan(start_idx));
      if (unlikely(!file)) {
        return MakeError(file);
      }
      start_idx += file->SerializedSize();
      this->variable_.files_.emplace_back(*file);
    }
    for (size_t idx = 0; idx < this->constant_.n_vmareas_; idx++) {
      auto const &vmarea =
          VMAreaMetadata::FromBytes(serialized.subspan(start_idx));
      if (unlikely(!vmarea)) {
        return MakeError(vmarea);
      }
      start_idx += vmarea->SerializedSize();
      this->variable_.vmareas_.emplace_back(*vmarea);
    }
    for (size_t idx = 0; idx < this->constant_.n_pending_signals_; idx++) {
      auto const &signal = SiginfoFromBytes(
          serialized.subspan(start_idx, start_idx + sizeof(siginfo_t)));
      start_idx += sizeof(siginfo_t);
      if (unlikely(!signal)) {
        return MakeError(signal);
      }
      this->variable_.pending_signals_.emplace_back(*signal);
    }
    for (size_t idx = 0; idx < this->constant_.n_child_procs_; idx++) {
      auto const &child_proc =
          ProcessMetadata::FromBytes(serialized.subspan(start_idx));
      if (unlikely(!child_proc)) {
        return MakeError(child_proc);
      }
      start_idx += child_proc->SerializedSize();
      this->variable_.child_procs_.emplace_back(*child_proc);
    }
    return {};
  }
  static Status<ProcessMetadata> FromBytes(
      std::span<const std::byte> serialized) {
    ProcessMetadata pm;
    auto const &constant = pm.DeserializeConstant(
        serialized.subspan(0, sizeof(ConstantProcessMetadata)));
    if (unlikely(!constant)) {
      return MakeError(constant);
    }

    auto const &variable = pm.DeserializeVariable(serialized.subspan(
        sizeof(ConstantProcessMetadata),
        serialized.size() - sizeof(ConstantProcessMetadata)));
    if (unlikely(!variable)) {
      return MakeError(variable);
    }

    return pm;
  }

  thread_tf GetTrapframe() const & { return constant_.GetTrapframe(); }
  pid_t GetPid() const & { return constant_.GetPid(); }
  pid_t GetPgid() const & { return constant_.GetPgid(); }
  int GetXstate() const & { return constant_.GetXstate(); }
  bool GetExited() const & { return constant_.GetExited(); }
  rlimit GetLimitNofile() const & { return constant_.GetLimitNofile(); }

  uintptr_t GetMemoryMapBrkAddr() const & {
    return constant_.GetMemoryMapBrkAddr();
  };
  uintptr_t GetMemoryMapBase() const & { return constant_.GetMemoryMapBase(); };
  uintptr_t GetMemoryMapLen() const & { return constant_.GetMemoryMapLen(); };
  uint64_t GetSignalQueuePending() const & {
    return constant_.GetSignalQueuePending();
  };
  std::span<const k_sigaction> GetSignalTable() const & {
    return constant_.GetSignalTable();
  }

  std::string_view GetBinaryPath() const & { return variable_.GetBinaryPath(); }
  std::span<const ThreadMetadata> GetThreads() const & {
    return variable_.GetThreads();
  }
  std::span<const ProcessMetadata> GetChildProcs() const & {
    return variable_.GetChildProcs();
  }
  std::span<const FileMetadata> GetFiles() const & {
    return variable_.GetFiles();
  }
  std::span<const VMAreaMetadata> GetVMAreas() const & {
    return variable_.GetVMAreas();
  }
  std::span<const siginfo_t> GetPendingSignals() const & {
    return variable_.GetPendingSignals();
  }

 private:
#pragma pack(push, 1)
  class ConstantProcessMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      s.MetadataPush(
          {reinterpret_cast<std::byte const *>(this), SerializedSize()});
    }
    size_t SerializedSize() const & { return sizeof(ConstantProcessMetadata); }
    void SetTrapframe(thread_tf const tf) {
      trapframe_ = tf;
      trapframe_.orig_rax = 0;
    }

    void SetProcId(pid_t const pid) { proc_pid_ = pid; }
    void SetProcGid(pid_t const pgid) { proc_pgid_ = pgid; }
    void SetProcExitState(int const xstate) {
      proc_xstate_ = xstate;
      proc_exited_ = true;
    }
    void SetProcLimitNumberOfFiles(rlimit limit_nofile) {
      proc_limit_nofile_cur_ = limit_nofile.rlim_cur;
      proc_limit_nofile_max_ = limit_nofile.rlim_max;
    }

    void SetFileTableLockIsHeld(
        bool is_held) { /* file_table_lock_is_held_ = is_held; */
    }

    void SetMemoryMapLockIsHeld(
        bool is_held) { /* memory_map_lock_is_held_ = is_held; */
    }
    void SetMemoryMapBreakAddr(uintptr_t brk_addr) {
      memory_map_brk_addr_ = brk_addr;
    }
    void SetMemoryMapBase(uintptr_t base) { memory_map_base_ = base; }
    void SetMemoryMapLen(uintptr_t len) { memory_map_len_ = len; }

    void SetITimerInterval(Duration interval) {
      itimer_interval_ms_ = interval.Microseconds();
    }
    void SetITimerNextFire(Time next_fire) {
      itimer_has_next_fire_ = true;
      itimer_next_fire_ms_ = next_fire.Microseconds();
    }

    void SetSignalQueuePending(uint64_t pending) {
      signal_queue_pending_ = pending;
    }
    void AddSignalTableEntry(size_t idx, k_sigaction const &sigaction) {
      signal_table_[idx] = sigaction;
    }

    void SetBinaryPath(std::string const &binary_path) {
      binary_path_sz_ = binary_path.size();
    }

    void ReserveNThreads(size_t const n_threads) { n_threads_ = n_threads; }
    void ReserveNChildProcs(size_t const n_children) {
      n_child_procs_ = n_children;
    }
    void ReserveNFiles(size_t const n_files) { n_files_ = n_files; }
    void ReserveNVMAreas(size_t const n_vmas) { n_vmareas_ = n_vmas; }
    void ReserveNPendingSignals(size_t const n_signals) {
      n_pending_signals_ = n_signals;
    }

    thread_tf GetTrapframe() const & { return trapframe_; }
    pid_t GetPid() const & { return proc_pid_; }
    pid_t GetPgid() const & { return proc_pgid_; }
    int GetXstate() const & { return proc_xstate_; }
    bool GetExited() const & { return proc_exited_; }
    rlimit GetLimitNofile() const & {
      return {
          .rlim_cur = proc_limit_nofile_cur_,
          .rlim_max = proc_limit_nofile_max_,
      };
    }

    uintptr_t GetMemoryMapBrkAddr() const & { return memory_map_brk_addr_; };
    uintptr_t GetMemoryMapBase() const & { return memory_map_base_; };
    uintptr_t GetMemoryMapLen() const & { return memory_map_len_; };

    /** TODO(snapshot): figure out how to construct an ITimer from the
    milliseconds ITimer GetItimer() const & { return itimer_interval_ms_; };
    std::optional<ITimer> GetNextFireItimer() const & {
        if (itimer_has_next_fire_) { return itimer_next_fire_ms_; }
        return {}
    }
    */

    uint64_t GetSignalQueuePending() const & { return signal_queue_pending_; };
    std::span<const k_sigaction> GetSignalTable() const & {
      return std::span(signal_table_);
    }

   private:
    friend ProcessMetadata;
    thread_tf trapframe_;

    pid_t proc_pid_;
    pid_t proc_pgid_;
    int proc_xstate_{0};
    bool proc_exited_{false};
    rlim_t proc_limit_nofile_cur_;
    rlim_t proc_limit_nofile_max_;

    uintptr_t memory_map_brk_addr_;
    uintptr_t memory_map_base_;
    uintptr_t memory_map_len_;

    uint64_t itimer_interval_ms_;
    bool itimer_has_next_fire_;
    uint64_t itimer_next_fire_ms_;

    uint64_t signal_queue_pending_;
    std::array<k_sigaction, kNumSignals> signal_table_;

    size_t binary_path_sz_;
    size_t n_threads_;
    size_t n_child_procs_;
    size_t n_files_;
    size_t n_vmareas_;
    size_t n_pending_signals_;
  };
#pragma pack(pop)

  class VariableLengthProcessMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      // binary path
      s.MetadataPush(
          std::as_bytes(std::span{binary_path_.data(), binary_path_.size()}));

      // threads
      for (auto const &thread : threads_) {
        thread.Serialize(s);
      }

      // files
      for (auto const &file : files_) {
        file.Serialize(s);
      }

      // vmareas
      for (auto const &vmarea : vmareas_) {
        vmarea.Serialize(s);
      }

      // pending signals
      for (auto const &sig : pending_signals_) {
        SiginfoSerialize(s, sig);
      }

      // child procs
      for (auto const &child : child_procs_) {
        child.Serialize(s);
      }
    }
    size_t SerializedSize() const & {
      size_t size = 0;
      // binary path
      size += binary_path_.size();

      // threads
      for (auto const &thread : threads_) {
        size += thread.SerializedSize();
      }

      // child procs
      for (auto const &child : child_procs_) {
        size += child.SerializedSize();
      }

      // files
      for (auto const &file : files_) {
        size += file.SerializedSize();
      }

      // vmareas
      for (auto const &vmarea : vmareas_) {
        size += vmarea.SerializedSize();
      }

      // pending signals
      size += sizeof(siginfo_t) * pending_signals_.size();

      return size;
    }

    void SetBinaryPath(std::string const &binary_path) {
      binary_path_ = binary_path;
    }

    void ReserveNThreads(size_t const n_threads) {
      threads_.reserve(n_threads);
    }
    void AddThread(ThreadMetadata const &thread) { threads_.push_back(thread); }

    void ReserveNChildProcs(size_t const n_children) {
      child_procs_.reserve(n_children);
    }
    void AddChildProc(ProcessMetadata const *const m) {
      child_procs_.push_back(*m);
    }

    void ReserveNFiles(size_t const n_files) { files_.reserve(n_files); }
    void AddFile(FileMetadata const &file) { files_.push_back(file); }

    void ReserveNVMAreas(size_t const n_vmas) { vmareas_.reserve(n_vmas); }
    void AddVMArea(VMAreaMetadata const &vma) { vmareas_.push_back(vma); }

    void ReserveNPendingSignals(size_t const n_signals) {
      pending_signals_.reserve(n_signals);
    }
    void AddPendingSignal(siginfo_t const &sig) {
      pending_signals_.push_back(sig);
    }

    std::string_view GetBinaryPath() const & { return binary_path_; }
    std::span<const ThreadMetadata> GetThreads() const & { return threads_; }
    std::span<const ProcessMetadata> GetChildProcs() const & {
      return child_procs_;
    }
    std::span<const FileMetadata> GetFiles() const & { return files_; }
    std::span<const VMAreaMetadata> GetVMAreas() const & { return vmareas_; }
    std::span<const siginfo_t> GetPendingSignals() const & {
      return pending_signals_;
    }

   private:
    friend ProcessMetadata;
    std::string binary_path_;

    std::vector<ThreadMetadata> threads_;
    std::vector<ProcessMetadata> child_procs_;
    std::vector<FileMetadata> files_;
    std::vector<VMAreaMetadata> vmareas_;
    std::vector<siginfo_t> pending_signals_;
  };

  ConstantProcessMetadata constant_;
  VariableLengthProcessMetadata variable_;
};

Status<ProcessMetadata> ReadProcessMetadata(std::string const &path);

}  // namespace junction
