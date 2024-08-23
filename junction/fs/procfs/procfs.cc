
#include "junction/fs/procfs/procfs.h"

#include <charconv>
#include <iomanip>

#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/fs/procfs/seqfile.h"
#include "junction/kernel/proc.h"

namespace junction::procfs {

inline static constexpr std::string_view kTaskDirName = "task";
inline static constexpr std::string_view kFDDirName = "fd";

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

std::string GetMounts(IDir *) {
  return "tmpfs / tmpfs rw,nosuid,nodev,inode64 0 0\n";
}

std::optional<int> ParseInt(std::string_view s) {
  int result;
  if (std::from_chars(s.data(), s.data() + s.size(), result).ec == std::errc{})
    return result;
  return std::nullopt;
}

ProcFSData::~ProcFSData() {
  if (ent_) ent_->get_parent_dir_locked().Unmount(ent_->get_name_locked());
}

std::string GetPidString(IDir *) { return std::to_string(myproc().get_pid()); }

template <std::string (*Gen)(IDir *)>
class ProcFSLink : public ISoftLink {
 public:
  ProcFSLink(mode_t mode, std::shared_ptr<IDir> parent = {})
      : ISoftLink(mode, AllocateInodeNumber()), parent_(std::move(parent)) {}

  bool SnapshotPrunable() override { return true; }

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

  bool SnapshotPrunable() override { return true; }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override {
    return std::make_shared<SeqFile>(flags, std::move(dent),
                                     Gen(parent_.get()));
  }

 private:
  std::shared_ptr<IDir> parent_;
};

// /proc/<pid>/task/<tid>
class ThreadDir : public memfs::MemIDir {
 public:
  ThreadDir(Token token, Thread &t)
      : MemIDir(token, 0555),
        proc_(t.get_process().weak_from_this()),
        tid_(t.get_tid()) {}

  bool SnapshotPrunable() override { return true; }

 protected:
  void DoInitialize() override {}

 private:
  std::weak_ptr<Process> proc_;
  pid_t tid_;
};

#if 0
// /proc/<pid>/fd
class FDDir : public memfs::MemIDir {
 public:
  FDDir(Token t) : MemIDir(t, 0555) {}
  ~FDDir() override = default;

  Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(std::string_view name)
  override {
    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<Process> &proc = *tmp;

    std::optional<int> fd = ParseInt(name);
    if (!fd) return MakeError(ENOENT);

    FileTable &ftbl = proc->get_file_table();
    File *f = ftbl.Get(*fd);
    if (!f) return MakeError(ENOENT);
    return GetFDLink(*f, *fd).get_this();
  }

  std::vector<dir_entry> GetDents() override {
    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return {};
    std::shared_ptr<Process> &proc = *tmp;

    std::vector<dir_entry> ret;
    FileTable &ftbl = proc->get_file_table();
    ftbl.ForEach([&](File &f, int fd) {
      ret.emplace_back(std::to_string(fd), 0, kTypeSymLink | 0777);
    });
    return ret;
  }

 private:
  DirectoryEntry &GetFDLink(File &f, int fd) {
    ProcFSData &data = f.get_procfs();
    if (!data.ent_) {
      Status<std::shared_ptr<ISoftLink>> ino = memfs::CreateISoftLink(f.get_filename());
      data.ent_ = InsertLockedNoCheck(std::to_string(fd), std::move(*ino));
    }
    return *data.ent_.get();
  }

  Status<std::shared_ptr<Process>> GetProcess();
};
#endif

// /proc/<pid>/task
class TaskDir : public memfs::MemIDir {
 public:
  TaskDir(Token t) : MemIDir(t, 0555) {}
  ~TaskDir() override = default;

  bool SnapshotPrunable() override { return true; }

  Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(
      std::string_view name) override {
    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<Process> &proc = *tmp;

    std::optional<int> tid = ParseInt(name);
    if (tid) {
      Status<ThreadRef> th = proc->FindThread(*tid);
      if (!th) return MakeError(ENOENT);
      return GetThreadDir(***th).shared_from_this();
    }
    DoInitCheckLocked();
    return MemIDir::LookupMissLocked(name);
  }

  std::vector<dir_entry> GetDents() override {
    DoInitCheck();

    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return {};
    std::shared_ptr<Process> &proc = *tmp;
    // Populate dentries.
    {
      rt::ScopedLock g(lock_);
      proc->ForEachThread([&](Thread &t) { GetThreadDir(t); });
    }
    return MemIDir::GetDents();
  }

 protected:
  void DoInitialize() override {}

 private:
  DirectoryEntry &GetThreadDir(Thread &t) {
    assert_locked();
    ProcFSData &data = t.get_procfs();
    if (!data.ent_) {
      data.ent_ =
          AddIDirLockedNoCheck<ThreadDir>(std::to_string(t.get_tid()), t)
              ->shared_from_this();
    }
    return *data.ent_.get();
  }

  Status<std::shared_ptr<Process>> GetProcess();
};

// /proc/<pid>
class ProcessDir : public memfs::MemIDir {
 public:
  ProcessDir(Token t, Process &p)
      : MemIDir(t, 0555), proc_(p.weak_from_this()) {}
  ~ProcessDir() override = default;

  Status<std::shared_ptr<Process>> GetProcess() {
    std::shared_ptr<Process> proc = proc_.lock();
    if (!proc) return MakeError(ESTALE);
    return std::move(proc);
  }

  bool SnapshotPrunable() override { return true; }

  bool is_dead() const { return proc_.use_count() == 0; }

 protected:
  void DoInitialize() override {
    if (is_dead()) return;
    AddDentLockedNoCheck(
        "exe", std::make_shared<ProcFSLink<GetExe>>(0777, get_this()));
    AddDentLockedNoCheck(
        "cmdline", std::make_shared<ProcFSInode<GetCmdLine>>(0444, get_this()));
    AddIDirLockedNoCheck<TaskDir>(std::string(kTaskDirName));
    // AddDentLockedNoCheck>(std::string(kFDDirName));
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
  ProcRootDir(Token t) : MemIDir(t, 0555) {}

  Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(
      std::string_view name) override {
    std::optional<int> tmp = ParseInt(name);

    if (tmp) {
      std::shared_ptr<Process> proc = Process::Find(*tmp);
      if (!proc) return MakeError(ENOENT);
      return GetProcDir(*proc.get()).shared_from_this();
    }

    DoInitCheckLocked();
    return MemIDir::LookupMissLocked(name);
  }

  bool SnapshotPrunable() override { return true; }

  std::vector<dir_entry> GetDents() override {
    DoInitCheck();
    // Ensure dentries are populated.
    {
      rt::ScopedLock g(lock_);
      Process::ForEachProcess([&](Process &p) { GetProcDir(p); });
    }
    return MemIDir::GetDents();
  }

 protected:
  void DoInitialize() override {
    AddDentLockedNoCheck("self",
                         std::make_shared<ProcFSLink<GetPidString>>(0777));
    AddDentLockedNoCheck("stat",
                         std::make_shared<ProcFSInode<GetMemInfo>>(0444));
    AddDentLockedNoCheck("mounts",
                         std::make_shared<ProcFSInode<GetMounts>>(0444));
  }

 private:
  DirectoryEntry &GetProcDir(Process &p) {
    assert_locked();
    ProcFSData &data = p.get_procfs();
    if (!data.ent_) {
      // TODO make this flow better.
      data.ent_ =
          AddIDirLockedNoCheck<ProcessDir>(std::to_string(p.get_pid()), p)
              ->shared_from_this();
    }
    return *data.ent_.get();
  }
};

Status<std::shared_ptr<Process>> TaskDir::GetProcess() {
  ProcessDir &dir =
      static_cast<ProcessDir &>(get_entry_ref().get_parent_dir_locked());
  return dir.GetProcess();
}

#if 0
Status<std::shared_ptr<Process>> FDDir::GetProcess() {
  ProcessDir &dir = 
      static_cast<ProcessDir &>(get_entry_ref().get_parent_dir_locked());
  return dir.GetProcess();
}
#endif

void MakeProcFS(IDir &root, std::string mount_name) {
  root.AddIDirNoCheck<ProcRootDir>(std::move(mount_name));
}

}  // namespace junction::procfs

// namespace junction::procfs