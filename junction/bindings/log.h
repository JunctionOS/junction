// log.h - support for printing to a log

#pragma once

extern "C" {
#include "base/log.h"
}

#include <iomanip>
#include <optional>
#include <spanstream>

#include "junction/bindings/runtime.h"

namespace junction::rt {

inline constexpr size_t kMaxLogBuf = 2048;

class Logger {
 public:
  explicit Logger(int level) noexcept {
    uint64_t us = microtime();
    RuntimeLibcGuard guard_;
    buf_.emplace(storage_);
    *buf_ << "[" << std::setw(3) << (int)(us / ONE_SECOND) << "."
          << std::setw(6) << std::setfill('0') << (int)(us % ONE_SECOND)
          << "] CPU " << std::setw(2) << std::setfill('0') << sched_getcpu()
          << "| <" << level << "> ";
  }
  ~Logger();

  template <typename T>
  Logger &operator<<(T const &value) {
    RuntimeLibcGuard guard_;

    if (unlikely(ss_)) {
      // Overflow storage is activated.
      *ss_ << value;
      return *this;
    }

    assert(!buf_->fail());
    off_t prev_off = buf_->tellp();
    *buf_ << value;
    if (unlikely(buf_->fail())) {
      // If we overflowed the array, switch to a dynamic
      // stream. Erase previously written bytes from value and rewrite them.
      ss_.emplace();
      buf_->seekp(prev_off);
      *ss_ << value;
    }

    return *this;
  }

 private:
  std::array<char, kMaxLogBuf> storage_;
  // buf_ is optional so that we can construct it under the RuntimeLibcGuard.
  std::optional<std::ospanstream> buf_;
  std::optional<std::ostringstream> ss_;
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
