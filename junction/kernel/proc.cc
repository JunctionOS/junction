extern "C" {
#include <sys/types.h>
}

#include <cstdlib>

#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

pid_t usys_getpid() { return 0; }

}  // namespace junction
