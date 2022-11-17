#include "junction/junction.hpp"

#include "junction/bindings/log.h"
#include "junction/syscall/dispatch.hpp"
#include "junction/syscall/seccomp.hpp"

namespace junction {

int init() {
  install_seccomp_filter();
  init_glibc_dispatcher();
  return 0;
}

}  // namespace junction
