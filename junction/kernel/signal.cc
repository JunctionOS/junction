#include "junction/kernel/usys.h"

extern "C" {
#include <signal.h>
}

#include "junction/kernel/proc.h"

namespace junction {

long usys_rt_sigaction(int sig, const struct sigaction *action,
                       struct sigaction *oact, size_t sigsetsize) {
  return 0;
}

long usys_rt_sigprocmask(int how, const kernel_sigset_t *nset,
                         kernel_sigset_t *oset, size_t sigsetsize) {
  // Note:
  // We don't change anything in terms of signal delivery to the process;
  // just keeping the signal set and returning it back when requested.
  assert(sigsetsize == kSigSetSizeBytes);

  Thread &tstate = mythread();
  kernel_sigset_t s = tstate.get_sigset();

  if (oset) {
    *oset = s;
  }

  if (nset) {
    if (how == SIG_BLOCK) {
      s.sig |= nset->sig;
    } else if (how == SIG_UNBLOCK) {
      s.sig &= ~(nset->sig);
    } else if (how == SIG_SETMASK) {
      s.sig = nset->sig;
    } else {
      return -EINVAL;
    }
    tstate.set_sigset(s);
  }

  return 0;
}

long usys_sigaltstack(const stack_t *ss, stack_t *old_ss) { return 0; }

}  // namespace junction
