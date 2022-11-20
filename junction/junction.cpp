#include "junction/junction.hpp"

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfs.hpp"
#include "junction/kernel/fs.h"
#include "junction/syscall/seccomp.hpp"
#include "junction/syscall/syscall.hpp"

namespace junction {

Status<void> init() {
  set_fs(new LinuxFileSystem());
  install_seccomp_filter();
  Status<void> ret = SyscallInit();
  if (unlikely(!ret)) return MakeError(ret);

  return {};
}

}  // namespace junction
