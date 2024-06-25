
#include "junction/fs/procfs/procfs.h"

#include <charconv>
#include <iomanip>

#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/fs/procfs/seqfile.h"
#include "junction/kernel/proc.h"

namespace junction::procfs {

std::string GetMemInfo(IDir *) {
  auto free = kMemoryMappingSize - myproc().get_mem_map().VirtualUsage();
  std::stringstream ss;
  ss << "MemTotal:       " << std::setw(8) << kMemoryMappingSize / 1024
     << " kB\n";
  ss << "MemFree:        " << std::setw(8) << free / 1024 << " kB\n";

  // Fake remaining ones:
  ss << "Buffers:               0 kB\n";
  ss << "Cached:                0 kB\n";
  ss << "MemShared:             0 kB\n";
  ss << "Active:                0 kB\n";
  ss << "Inactive:              0 kB\n";
  return ss.str();
}

std::string GetPidString(IDir *) { return std::to_string(myproc().get_pid()); }

template <std::string (*Gen)(IDir *)>
class ProcFSLink : public ISoftLink {
 public:
  ProcFSLink(mode_t mode, std::shared_ptr<IDir> parent = {})
      : ISoftLink(mode, AllocateInodeNumber()), parent_(std::move(parent)) {}

  std::string ReadLink() const override { return Gen(parent_.get()); };

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

 private:
  std::shared_ptr<IDir> parent_;
};

template <std::string (*Gen)(IDir *)>
class ProcFSInode : public Inode {
 public:
  ProcFSInode(mode_t mode, std::shared_ptr<IDir> parent = {})
      : Inode(kTypeRegularFile | mode, AllocateInodeNumber()),
        parent_(std::move(parent)) {}

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(uint32_t flags, FileMode mode) override {
    return std::make_shared<SeqFile>(flags, get_this(), Gen(parent_.get()));
  }

 private:
  std::shared_ptr<IDir> parent_;
};

std::optional<pid_t> ParsePid(std::string_view s) {
  pid_t result;
  if (std::from_chars(s.data(), s.data() + s.size(), result).ec == std::errc{})
    return result;
  return std::nullopt;
}

// /proc/<pid>/task/<tid>
class ThreadDir : public memfs::MemIDir {
 public:
  ThreadDir(Thread &t, std::shared_ptr<IDir> parent)
      : MemIDir(0555, std::to_string(t.get_tid()), std::move(parent)),
        proc_(t.get_process().weak_from_this()),
        tid_(t.get_tid()) {}

  [[nodiscard]] std::string get_name() const { return get_static_name(); }

 protected:
  void DoInitialize() override {}

 private:
  std::weak_ptr<Process> proc_;
  pid_t tid_;
};

// /proc/<pid>/task
class TaskDir : public memfs::MemIDir {
 public:
  TaskDir(std::shared_ptr<IDir> parent)
      : MemIDir(0555, std::string(kTaskDirName), std::move(parent)) {}
  ~TaskDir() override = default;

  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override {
    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<Process> &proc = *tmp;

    std::optional<pid_t> tid = ParsePid(name);
    if (tid) {
      Status<ThreadRef> th = proc->FindThread(*tid);
      if (!th) return MakeError(ENOENT);
      return GetThreadDir(***th).get_this();
    }
    DoInitCheck();
    return MemIDir::Lookup(name);
  }

  std::vector<dir_entry> GetDents() override {
    DoInitCheck();

    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return {};
    std::shared_ptr<Process> &proc = *tmp;

    auto result = MemIDir::GetDents();

    rt::ScopedLock g(lock_);
    proc->ForEachThread([&](Thread &t) {
      ThreadDir &dir = GetThreadDir(t);
      result.emplace_back(dir.get_name(), dir.get_inum(), dir.get_type());
    });

    return result;
  }

 protected:
  void DoInitialize() override {}

 private:
  ThreadDir &GetThreadDir(Thread &t) {
    ProcFSData &data = t.get_procfs();
    if (!data.dir_) {
      data.dir_ = std::make_shared<ThreadDir>(t, get_this());
      data.dir_->inc_nlink();
    }
    return *std::static_pointer_cast<ThreadDir>(data.dir_).get();
  }

  Status<std::shared_ptr<Process>> GetProcess();

  inline static constexpr std::string_view kTaskDirName = "task";
};

// /proc/<pid>
class ProcessDir : public memfs::MemIDir {
 public:
  ProcessDir(Process &p, std::shared_ptr<IDir> parent)
      : MemIDir(0555, std::to_string(p.get_pid()), std::move(parent)),
        proc_(p.weak_from_this()) {}
  ~ProcessDir() override = default;

  [[nodiscard]] std::string get_name() const { return get_static_name(); }

  Status<std::shared_ptr<Process>> GetProcess() {
    std::shared_ptr<Process> proc = proc_.lock();
    if (!proc) return MakeError(ESTALE);
    return std::move(proc);
  }

  bool is_dead() const { return proc_.use_count() == 0; }

 protected:
  void DoInitialize() override {
    if (is_dead()) return;
    InsertLockedNoCheck("exe",
                        std::make_shared<ProcFSLink<GetExe>>(0777, get_this()));
    InsertLockedNoCheck(
        "cmdline", std::make_shared<ProcFSInode<GetCmdLine>>(0444, get_this()));
    InsertLockedNoCheck("task", std::make_shared<TaskDir>(get_this()));
  }

 private:
  static std::string GetExe(IDir *parent) {
    assert(parent);
    ProcessDir &dir = static_cast<ProcessDir &>(*parent);
    std::shared_ptr<Process> p = dir.proc_.lock();
    if (!p) return "[stale]";
    return std::string(p->get_mem_map().get_bin_path());
  }

  static std::string GetCmdLine(IDir *parent) {
    assert(parent);
    ProcessDir &dir = static_cast<ProcessDir &>(*parent);
    std::shared_ptr<Process> p = dir.proc_.lock();
    if (!p) return "[stale]";
    return std::string(p->get_mem_map().get_cmd_line());
  }

  std::weak_ptr<Process> proc_;
};

// /proc
class ProcRootDir : public memfs::MemIDir {
 public:
  ProcRootDir(std::shared_ptr<IDir> parent)
      : MemIDir(0555, std::string{"proc"}, std::move(parent)) {}

  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override {
    std::optional<pid_t> tmp = ParsePid(name);

    if (tmp) {
      std::shared_ptr<Process> proc = Process::Find(*tmp);
      if (!proc) return MakeError(ENOENT);

      rt::ScopedLock g(lock_);
      return GetProcDir(*proc.get()).get_this();
    }

    DoInitCheck();
    return MemIDir::Lookup(name);
  }

  std::vector<dir_entry> GetDents() override {
    DoInitCheck();
    std::vector<dir_entry> result = MemIDir::GetDents();

    rt::ScopedLock g(lock_);
    Process::ForEachProcess([&](Process &p) {
      ProcessDir &dir = GetProcDir(p);
      result.emplace_back(dir.get_name(), dir.get_inum(), dir.get_type());
    });

    return result;
  }

 protected:
  void DoInitialize() override {
    InsertLockedNoCheck("self",
                        std::make_shared<ProcFSLink<GetPidString>>(0777));
    InsertLockedNoCheck("stat",
                        std::make_shared<ProcFSInode<GetMemInfo>>(0444));
  }

 private:
  ProcessDir &GetProcDir(Process &p) {
    assert(lock_.IsHeld());
    ProcFSData &data = p.get_procfs();
    if (!data.dir_) {
      data.dir_ = std::make_shared<ProcessDir>(p, get_this());
      data.dir_->inc_nlink();
    }
    return *std::static_pointer_cast<ProcessDir>(data.dir_).get();
  }
};

Status<std::shared_ptr<Process>> TaskDir::GetProcess() {
  ProcessDir &dir = static_cast<ProcessDir &>(get_static_parent());
  return dir.GetProcess();
}

std::shared_ptr<Inode> MakeProcFS(std::shared_ptr<IDir> parent) {
  return std::make_shared<ProcRootDir>(std::move(parent));
}

}  // namespace junction::procfs