// misc.cc - miscellaneous system calls

extern "C" {
#include <asm/unistd_64.h>
}

#include "junction/kernel/ksys.h"
#include "junction/kernel/usys.h"

namespace junction {

ssize_t usys_getcwd(char *buf, size_t size) {
  // TODO(amb): Remove this once the filesystem is more there
  return ksys_default(reinterpret_cast<unsigned long>(buf), size, 0, 0, 0, 0,
                      __NR_getcwd);
}

}  // namespace junction
