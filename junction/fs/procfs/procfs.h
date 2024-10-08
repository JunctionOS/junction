#pragma once

#include <memory>

namespace junction {

class DirectoryEntry;
class IDir;

namespace procfs {

class ProcFSData {
 public:
  ProcFSData() = default;
  ~ProcFSData();

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