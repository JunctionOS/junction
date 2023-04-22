// log.h - support for printing to a log

#pragma once

extern "C" {
#include "base/log.h"
}

#include <sstream>
#include <string>

#include "junction/bindings/runtime.h"

namespace junction::rt {

// TODO(amb): This allocates memory each use. Use std::ospanstream (C++23)?
class Logger {
 public:
  explicit Logger(int level) noexcept : level_(level) {}
  ~Logger();

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
#define LOG(level) \
  if (LOG_##level <= max_loglevel) rt::Logger(LOG_##level)

// LOG_ONCE appends a line to the log at the specified log level, only once.
// Example:
//   LOG_ONCE(ERR) << "error happened that could repeat";
#define LOG_ONCE(level)                      \
  if (auto pred =                            \
          [] {                               \
            static bool once = false;        \
            if (unlikely(!once)) {           \
              once = true;                   \
              return true;                   \
            }                                \
            return false;                    \
          };                                 \
      LOG_##level <= max_loglevel && pred()) \
  rt::Logger(LOG_##level)

// DLOG behaves like LOG in debug mode. Otherwise it compiles away to nothing.
// Example:
//  DLOG(INFO) << "system started";
#ifdef DEBUG
#define DLOG(level) \
  if (LOG_##level <= max_loglevel) rt::Logger(LOG_##level)
#else  // DEBUG
#define DLOG(level) \
  if (false) rt::Logger(LOG_##level)
#endif  // DEBUG

// DLOG_ONCE behaves like LOG_ONCE in debug mode. Otherwise it compiles away.
// Example:
//   DLOG_ONCE(ERR) << "error happened that could repeat";
#ifdef DEBUG
#define DLOG_ONCE(level)                     \
  if (auto pred =                            \
          [] {                               \
            static bool once = false;        \
            if (unlikely(!once)) {           \
              once = true;                   \
              return true;                   \
            }                                \
            return false;                    \
          };                                 \
      LOG_##level <= max_loglevel && pred()) \
  rt::Logger(LOG_##level)
#else  // DEBUG
#define DLOG_ONCE(level) \
  if (false) rt::Logger(LOG_##level)
#endif  // DEBUG

}  // namespace junction::rt
