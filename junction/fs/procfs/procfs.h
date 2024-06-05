#pragma once

#include "junction/fs/fs.h"

namespace junction {

std::shared_ptr<Inode> MakeMemInfo();
std::shared_ptr<Inode> MakeSelfExe();

}  // namespace junction