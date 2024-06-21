#pragma once

#include "junction/fs/fs.h"

namespace junction::procfs {

class ProcFSData {
 public:
  ProcFSData() = default;
  ~ProcFSData() {
    if (dir_) dir_->dec_nlink();
  }

 private:
  friend class ProcRootDir;
  friend class TaskDir;
  std::shared_ptr<IDir> dir_;
};

std::shared_ptr<Inode> MakeProcFS(std::shared_ptr<IDir> parent);

}  // namespace junction::procfs