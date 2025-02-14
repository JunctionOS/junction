// log.cc - support for printing to a log

#include "junction/bindings/log.h"

extern "C" {
#include <base/syscall.h>
}

namespace junction::rt {

Logger::~Logger() {
  RuntimeLibcGuard guard_;

  if (likely(!ss_)) {
    *buf_ << "\n";
    syscall_write(1, buf_->span().data(), buf_->span().size());
    return;
  }

  *ss_ << "\n";
  std::string overflow = ss_->str();

  struct iovec iov[2];
  iov[0].iov_base = buf_->span().data();
  iov[0].iov_len = buf_->span().size();
  iov[1].iov_base = overflow.data();
  iov[1].iov_len = overflow.size();
  syscall_writev(1, iov, 2);
}

}  // namespace junction::rt
