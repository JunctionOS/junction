// log.h - support for printing to a log

#pragma once

extern "C" {
#include "base/log.h"
}

#include <sstream>
#include <string>

namespace rt {

// TODO: This allocates memory each use. Use std::ospanstream (C++23) instead?
class Logger {
 public:
  explicit Logger(int level) noexcept : level_(level) {}
  ~Logger() { logk(level_, "%s", buf_.str().c_str()); }

  template <typename T>
  Logger &operator<<(T const &value) {
    buf_ << value;
    return *this;
  }

 private:
  int level_;
  std::ostringstream buf_;
};

// LOG appends a line to the log at the specified log level.
// Example:
//   LOG(INFO) << "system started";
#define LOG(level) rt::Logger(LOG_##level)

// DLOG behaves like LOG in debug mode. Otherwise it compiles away to nothing.
// Example:
//  DLOG(INFO) << "system started";
#ifdef DEBUG
#define DLOG(level) rt::Logger(LOG_##level)
#else  // DEBUG
#define DLOG(level) \
  if (false) rt::Logger(LOG_##level)
#endif  // DEBUG

}  // namespace rt
