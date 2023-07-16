#include "junction/syscall/strace.h"

extern "C" {
#include <signal.h>
}

#include "junction/bindings/log.h"

namespace junction {

const char *sigmap[] = {
    "SIGHUP",  "SIGINT",    "SIGQUIT", "SIGILL",    "SIGTRAP", "SIGABRT",
    "SIGBUS",  "SIGFPE",    "SIGKILL", "SIGUSR1",   "SIGSEGV", "SIGUSR2",
    "SIGPIPE", "SIGALRM",   "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT",
    "SIGSTOP", "SIGTSTP",   "SIGTTIN", "SIGTTOU",   "SIGURG",  "SIGXCPU",
    "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",  "SIGIO",   "SIGPWR",
    "SIGSYS",  "SIGUNUSED"};

void LogSignal(const siginfo_t &info) {
  const char *signame;
  if (info.si_signo > 0 && info.si_signo < 32)
    signame = sigmap[info.si_signo - 1];
  else
    signame = "unknown";

  LOG(INFO) << "[" << myproc().get_pid() << ":" << mythread().get_tid()
            << "] --- " << signame << " {si_signo=" << info.si_signo
            << ", si_code = " << info.si_code << ", si_addr = " << info.si_addr
            << "} ---";
}
}  // namespace junction