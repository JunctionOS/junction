extern "C" {
#include <sys/types.h>
}

#include <junction/bindings/log.h>

#include <cstdlib>

#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

pid_t usys_getpid() { return 0; }

void usys_exit_group(int status) {
  LOG(ERR) << "Exiting...";
  // TODO(jfried): this should only terminate this Proc
  ksys_exit(status);
}

}  // namespace junction
