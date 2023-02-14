#include "junction/kernel/usys.h"

extern "C" {
#include <signal.h>
}

namespace junction {

long usys_rt_sigaction(int sig, const struct sigaction *action,
                       struct sigaction *oact, size_t sigsetsize) {
  return 0;
}

long usys_rt_sigprocmask(int how, sigset_t *nset, sigset *oset,
                         size_t sigsetsize) {
  return 0;
}

}  // namespace junction
