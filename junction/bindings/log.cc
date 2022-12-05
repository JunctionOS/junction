#include "junction/bindings/log.h"

namespace junction::rt {

Logger::~Logger() {
  RuntimeLibcGuard guard;
  logk(level_, "%s", buf_.str().c_str());
}

}  // namespace junction::rt
