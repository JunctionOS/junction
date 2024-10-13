// log.cc - support for printing to a log

#include "junction/bindings/log.h"

extern "C" {
#include <base/syscall.h>
}

namespace junction::rt {

Logger::~Logger() {
  RuntimeLibcGuard guard_;
  *buf_ << '\n';
  syscall_write(1, buf_->span().data(), buf_->span().size());
}

}  // namespace junction::rt
