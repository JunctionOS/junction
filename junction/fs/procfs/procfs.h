#pragma once

#include <memory>

namespace junction {

class DirectoryEntry;
class IDir;

namespace procfs {

void ProcDirNotify(DirectoryEntry &ent, int fd);

class ProcFSData {
 public:
  ProcFSData() = default;
  ~ProcFSData();

  inline void NotifyFDDestroy(int fd) {
    if (ent_) ProcDirNotify(*ent_.get(), fd);
  }

 private:
  friend class ProcRootDir;
  friend class TaskDir;
  friend class FDDir;
  std::shared_ptr<DirectoryEntry> ent_;
};

void MakeProcFS(IDir &root, std::string mount_name);
void MakeSysFS(IDir &root, std::string mount_name);

}  // namespace procfs

}  // namespace junction