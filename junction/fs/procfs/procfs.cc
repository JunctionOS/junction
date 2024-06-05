
#include "junction/fs/procfs/procfs.h"

#include <iomanip>

#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/fs/procfs/seqfile.h"
#include "junction/kernel/proc.h"

namespace junction {

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

std::string GetBinaryName() { return std::string(myproc().get_bin_path()); }

template <std::string (*Gen)()>
class ProcFSInode : public Inode {
 public:
  ProcFSInode() : Inode(kTypeRegularFile | S_IRUSR, AllocateInodeNumber()) {}

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) override {
    return std::make_shared<SeqFile>(flags, kModeRead, get_this(), Gen());
  }
};

std::shared_ptr<Inode> MakeMemInfo() {
  return std::make_shared<ProcFSInode<GetMemInfo>>();
}

template <std::string (*Gen)()>
class ProcFSLink : public ISoftLink {
 public:
  ProcFSLink() : ISoftLink(S_IRUSR, AllocateInodeNumber()) {}

  std::string ReadLink() override { return Gen(); };

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }
};

std::shared_ptr<Inode> MakeSelfExe() {
  return std::make_shared<ProcFSLink<GetBinaryName>>();
}

}  // namespace junction