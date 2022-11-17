#include "junction/junction.hpp"

#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfs.hpp"
#include "junction/kernel/fs.h"
#include "junction/syscall/dispatch.hpp"
#include "junction/syscall/seccomp.hpp"

namespace junction {

int init() {
  set_fs(new LinuxFileSystem());
  install_seccomp_filter();
  init_glibc_dispatcher();

  return 0;
}

}  // namespace junction
