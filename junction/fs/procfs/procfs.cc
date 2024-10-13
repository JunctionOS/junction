
extern "C" {
#include "lib/caladan/runtime/defs.h"
}

#include <charconv>
#include <iomanip>

#include "junction/base/format.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/fs/procfs/procfs.h"
#include "junction/fs/procfs/seqfile.h"
#include "junction/kernel/proc.h"

namespace junction::procfs {

inline static constexpr std::string_view kTaskDirName = "task";
inline static constexpr std::string_view kFDDirName = "fd";

std::string GetMemInfo() {
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

std::string GetMounts() {
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

std::string GetPidString() { return std::to_string(myproc().get_pid()); }

class ProcFSLink : public memfs::MemISoftLink {
  using MemISoftLink::MemISoftLink;
  bool SnapshotPrunable() override { return true; }
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }
};

class ProcFSDir : public memfs::MemIDir {
  using MemIDir::MemIDir;
  bool SnapshotPrunable() override { return true; }
};

class ProcFSGenLink : public ISoftLink {
 public:
  ProcFSGenLink(mode_t mode, std::function<std::string()> func)
      : ISoftLink(mode, AllocateInodeNumber()), gen_(std::move(func)) {}
  std::string ReadLink() const override { return gen_(); };
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

 private:
  std::function<std::string()> gen_;
};

class ProcFSInode : public Inode {
 public:
  ProcFSInode(mode_t mode, std::function<std::string()> func)
      : Inode(kTypeRegularFile | mode, AllocateInodeNumber()),
        gen_(std::move(func)) {}

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  bool SnapshotPrunable() override { return true; }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override {
    return std::make_shared<SeqFile>(flags, std::move(dent), gen_());
  }

 private:
  std::function<std::string()> gen_;
};

template <typename Func>
std::shared_ptr<Inode> MakeInode(mode_t mode, Func func) {
  return std::make_shared<ProcFSInode>(mode, std::forward<Func>(func));
}

template <typename Func>
std::shared_ptr<Inode> MakeLink(mode_t mode, Func func) {
  return std::make_shared<ProcFSGenLink>(mode, std::forward<Func>(func));
}

// /proc/<pid>/fd
class FDDir : public ProcFSDir {
 public:
  FDDir(Token t) : ProcFSDir(t, 0555) {}
  ~FDDir() override = default;

  Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(
      std::string_view name) override {
    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<Process> &proc = *tmp;
    if (proc->exited()) return MakeError(ESTALE);

    std::optional<int> fd = ParseInt(name);
    if (!fd) return MakeError(ENOENT);

    FileTable &ftbl = proc->get_file_table();
    File *f = ftbl.Get(*fd);
    if (!f) return MakeError(ENOENT);
    return AddEntry(*f, *fd)->shared_from_this();
  }

  std::vector<dir_entry> GetDents() override {
    Status<std::shared_ptr<Process>> tmp = GetProcess();
    if (!tmp) return {};
    std::shared_ptr<Process> &proc = *tmp;
    if (proc->exited()) return {};

    FileTable &ftbl = proc->get_file_table();
    dynamic_bitmap present(ftbl.GetLen());

    // Update the dentry cache.
    {
      rt::ScopedLock g(lock_);

      ftbl.ForEach([&](File &f, int fd) {
        if (unlikely(static_cast<size_t>(fd) >= present.size()))
          present.resize(static_cast<size_t>(fd) * 2 + 1);
        present.set(fd);
        if (!check_entry(fd)) AddEntry(f, fd);
      });

      for_each_set_bit(fds_with_symlink_inodes_, [&](size_t i) {
        if (!present.test(i)) DeleteEntry(i);
      });
    }
    return MemIDir::GetDents();
  }

  void NotifyFdInvalidated(int fd) {
    rt::ScopedLock g(lock_);
    if (check_entry(fd)) DeleteEntry(fd);
  }

 private:
  DirectoryEntry *AddEntry(File &f, int fd) {
    assert(lock_.IsHeld());
    if (fds_with_symlink_inodes_.size() <= static_cast<size_t>(fd))
      fds_with_symlink_inodes_.resize(1 + fd * 2);
    fds_with_symlink_inodes_.set(fd);
    return AddDentLockedNoCheck(std::to_string(fd),
                                std::make_shared<ProcFSLink>(f.get_filename()));
  }

  void DeleteEntry(int fd) {
    assert(lock_.IsHeld());
    Status<DirectoryEntry *> dent = FindRaw(std::to_string(fd));
    if (dent) UnlinkAndDispose(*dent);
    fds_with_symlink_inodes_.clear(fd);
  }

  [[nodiscard]] bool check_entry(size_t fd) {
    if (fds_with_symlink_inodes_.size() <= fd) return false;
    return fds_with_symlink_inodes_.test(fd);
  }

  Status<std::shared_ptr<Process>> GetProcess();
  dynamic_bitmap fds_with_symlink_inodes_;
};

// /proc/<pid>/task
class TaskDir : public ProcFSDir {
 public:
  TaskDir(Token t) : ProcFSDir(t, 0555) {}
  ~TaskDir() override = default;

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
    return ProcFSDir::LookupMissLocked(name);
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
    return ProcFSDir::GetDents();
  }

 protected:
  void DoInitialize() override {}

 private:
  DirectoryEntry &GetThreadDir(Thread &t) {
    assert_locked();
    ProcFSData &data = t.get_procfs();
    if (!data.ent_) {
      data.ent_ =
          AddIDirLockedNoCheck<ProcFSDir>(std::to_string(t.get_tid()), 0555)
              ->shared_from_this();
    }
    return *data.ent_.get();
  }

  Status<std::shared_ptr<Process>> GetProcess();
};

// /proc/<pid>
class ProcessDir : public ProcFSDir {
 public:
  ProcessDir(Token t, Process &p)
      : ProcFSDir(t, 0555), proc_(p.weak_from_this()) {}
  ~ProcessDir() override = default;

  Status<std::shared_ptr<Process>> GetProcess() {
    std::shared_ptr<Process> proc = proc_.lock();
    if (!proc) return MakeError(ESTALE);
    return std::move(proc);
  }

  bool is_dead() const { return proc_.use_count() == 0; }

  void NotifyFdInvalidated(int fd) {
    if (!fd_dir_) return;
    fd_dir_->NotifyFdInvalidated(fd);
  }

 protected:
  void DoInitialize() override {
    if (is_dead()) return;
    AddDentLockedNoCheck("exe",
                         MakeLink(0777, [p = proc_] { return GetExe(p); }));
    AddDentLockedNoCheck(
        "cmdline", MakeInode(0444, [p = proc_] { return GetCmdLine(p); }));
    AddIDirLockedNoCheck<TaskDir>(std::string(kTaskDirName));
    DirectoryEntry *de = AddIDirLockedNoCheck<FDDir>(std::string(kFDDirName));
    fd_dir_ =
        static_cast<FDDir &>(de->get_inode_ref()).shared_from_base<FDDir>();
  }

 private:
  static std::string GetExe(std::weak_ptr<Process> proc) {
    std::shared_ptr<Process> p = proc.lock();
    if (!p) return "[stale]";
    return std::string(p->get_mem_map().get_bin_path());
  }

  static std::string GetCmdLine(std::weak_ptr<Process> proc) {
    std::shared_ptr<Process> p = proc.lock();
    if (!p) return "[stale]";
    return std::string(p->get_mem_map().get_cmd_line());
  }

  std::weak_ptr<Process> proc_;
  std::shared_ptr<FDDir> fd_dir_;
};

// /proc
class ProcRootDir : public ProcFSDir {
 public:
  ProcRootDir(Token t) : ProcFSDir(t, 0555) {}

  Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(
      std::string_view name) override {
    std::optional<int> tmp = ParseInt(name);

    if (tmp) {
      std::shared_ptr<Process> proc = Process::Find(*tmp);
      if (!proc) return MakeError(ENOENT);
      return GetProcDir(*proc.get()).shared_from_this();
    }

    DoInitCheckLocked();
    return ProcFSDir::LookupMissLocked(name);
  }

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
    AddDentLockedNoCheck("self", MakeLink(0777, GetPidString));
    AddDentLockedNoCheck("stat", MakeInode(0444, GetMemInfo));
    AddDentLockedNoCheck("mounts", MakeInode(0444, GetMounts));
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

Status<std::shared_ptr<Process>> FDDir::GetProcess() {
  ProcessDir &dir =
      static_cast<ProcessDir &>(get_entry_ref().get_parent_dir_locked());
  return dir.GetProcess();
}

void ProcDirNotify(DirectoryEntry &ent, int fd) {
  ProcessDir &pdir = fast_cast<ProcessDir &>(ent.get_inode_ref());
  pdir.NotifyFdInvalidated(fd);
}

std::shared_ptr<IDir> MkFolder(IDir &parent, std::string name, mode_t mode) {
  std::shared_ptr<DirectoryEntry> de =
      parent.AddIDirNoCheck<ProcFSDir>(std::move(name), mode);
  return static_cast<IDir &>(de->get_inode_ref()).get_this();
}

class SysRootDir : public ProcFSDir {
 public:
  SysRootDir(Token t) : ProcFSDir(t, 0555) {}

 protected:
  void DoInitialize() override {
    auto ent = AddIDirLockedNoCheck<ProcFSDir>("class", 0655);
    auto dir = MkFolder(static_cast<IDir &>(ent->get_inode_ref()), "net", 0655);
    dir = MkFolder(*dir.get(), "eth0", 0655);
    dir->Link("address", MakeInode(0444, GetMacAddr));

    ent = AddIDirLockedNoCheck<ProcFSDir>("devices", 0655);
    dir = MkFolder(static_cast<IDir &>(ent->get_inode_ref()), "system", 0655);
    dir = MkFolder(*dir.get(), "cpu", 0655);
    std::shared_ptr<Inode> cpuListIno = MakeInode(0444, GetCpus);
    dir->Link("online", cpuListIno);
    dir->Link("possible", std::move(cpuListIno));
  }

 private:
  static std::string GetCpus() {
    size_t cores = rt::RuntimeMaxCores();
    if (cores == 1) return "0\n";
    return std::format("0-{}\n", cores - 1);
  }

  static std::string GetMacAddr() {
    auto &mac = netcfg.mac.addr;
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", mac[0],
                       mac[1], mac[2], mac[3], mac[4], mac[5]);
  }
};

void MakeProcFS(IDir &root, std::string mount_name) {
  root.AddIDirNoCheck<ProcRootDir>(std::move(mount_name));
}

void MakeSysFS(IDir &root, std::string mount_name) {
  root.AddIDirNoCheck<SysRootDir>(std::move(mount_name));
}

}  // namespace junction::procfs

// namespace junction::procfs
