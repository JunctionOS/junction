#pragma once

#include <memory>

namespace junction {

class Inode;
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
  std::shared_ptr<Inode> in_;
};

std::shared_ptr<Inode> MakeProcFS(std::shared_ptr<IDir> parent);

}  // namespace procfs

}  // namespace junction