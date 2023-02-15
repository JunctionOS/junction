#include "junction/kernel/usys.h"

extern "C" {
#include <signal.h>
}

namespace junction {

long usys_rt_sigaction(int sig, const struct sigaction *action,
                       struct sigaction *oact, size_t sigsetsize) {
  return 0;
}

long usys_rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset,
                         size_t sigsetsize) {
  return 0;
}

long usys_sigaltstack(const stack_t *ss, stack_t *old_ss) { return 0; }

}  // namespace junction
