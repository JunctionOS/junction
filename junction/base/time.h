// time.h - utilities for measuring and representing time

#pragma once

extern "C" {
#include <base/time.h>
#include <sys/time.h>
}

#include <string>

namespace junction {

inline constexpr uint64_t kMilliseconds = 1000;
inline constexpr uint64_t kSeconds = 1000000;

namespace detail {

// Microtime returns microseconds since the launch of the runtime.
inline uint64_t MicroTime() { return microtime(); }

// Converts a Linux timeval into microseconds
constexpr uint64_t timeval_to_us(const timeval &tv) {
  return tv.tv_sec * kSeconds + tv.tv_usec;
}

// Converts microseconds into a Linux timeval
constexpr timeval us_to_timeval(uint64_t us) {
  return timeval{.tv_sec = static_cast<time_t>(us / kSeconds),
                 .tv_usec = static_cast<suseconds_t>(us % kSeconds)};
}

// Converts a Linux timespec into microseconds
constexpr uint64_t timespec_to_us(const timespec &ts) {
  return ts.tv_sec * kSeconds + ts.tv_nsec / 1000;
}

// Converts microseconds into a Linux timespec
constexpr timespec us_to_timespec(uint64_t us) {
  return timespec{.tv_sec = static_cast<time_t>(us / kSeconds),
                  .tv_nsec = static_cast<long>((us % kSeconds) * 1000)};
}

}  // namespace detail

class Time;

// Duration specifies an interval of time.
class Duration {
 public:
  constexpr explicit Duration(int64_t us) : duration_(us) {}
  constexpr explicit Duration(const timeval &tv)
      : duration_(detail::timeval_to_us(tv)) {}
  constexpr explicit Duration(const timespec &ts)
      : duration_(detail::timespec_to_us(ts)) {}
  constexpr ~Duration() = default;

  // Since returns the duration spanning from now to a time @t.
  static Duration Since(const Time &t);
  // Until returns the duration spanning from a time @t to now.
  static Duration Until(const Time &t);

  // Timeval converts the duration to a Linux timeval. Behavior is undefined if
  // the duration is negative.
  constexpr timeval Timeval() const { return detail::us_to_timeval(duration_); }
  // Timespec converts the duration to a Linux timespec. Behavior is udnefined
  // if the duration is negative.
  constexpr timespec Timespec() const {
    return detail::us_to_timespec(duration_);
  }

  // Microseconds converts the duration into microseconds (can be negative).
  constexpr int64_t Microseconds() const { return duration_; }

  // IsZero checks if the duration is zero.
  constexpr bool IsZero() const { return duration_ == 0; }

  // ToString converts to a string representation.
  //
  // TODO(amb): Make the formatting nicer.
  // Currently displayed in seconds (e.g., 5500 us would be '5.5s')
  std::string ToString() const {
    return std::to_string(static_cast<float>(duration_) /
                          static_cast<float>(kSeconds)) +
           "s";
  }

  // Enable comparisons
  constexpr auto operator<=>(const Duration &) const = default;

 private:
  int64_t duration_;
};

// Time specifies a point in time.
class Time {
 public:
  constexpr explicit Time(uint64_t us) : time_(us) {}
  constexpr explicit Time(const timeval &tv)
      : time_(detail::timeval_to_us(tv)) {}
  constexpr explicit Time(const timespec &ts)
      : time_(detail::timespec_to_us(ts)) {}
  constexpr ~Time() = default;

  // Now gets the current time.
  static Time Now() { return Time(detail::MicroTime()); }

  // Timeval converts the time to a Linux timeval.
  constexpr timeval Timeval() const { return detail::us_to_timeval(time_); }
  // Timespec converts the time to a Linux timespec.
  constexpr timespec Timespec() const { return detail::us_to_timespec(time_); }

  // Microseconds converts the time into microseconds.
  constexpr uint64_t Microseconds() const { return time_; }

  // ToString converts to a string representation.
  //
  // TODO(amb): Make the formatting nicer.
  // Currently displayed in seconds (e.g., 5500 us would be '5.5s')
  std::string ToString() const {
    return std::to_string(static_cast<float>(time_) /
                          static_cast<float>(kSeconds)) +
           "s";
  }

  // Enable comparisons
  constexpr auto operator<=>(const Time &) const = default;

  // A duration can be added or subtracted from the time.
  constexpr Time &operator+=(const Duration &rhs) {
    time_ += rhs.Microseconds();
    return *this;
  }
  constexpr Time &operator-=(const Duration &rhs) {
    time_ -= rhs.Microseconds();
    return *this;
  }

 private:
  uint64_t time_;
};

// Allow Duration and Time to interact with + and - operators.
constexpr inline Time operator+(const Time &lhs, const Duration &rhs) {
  return Time(lhs.Microseconds() + rhs.Microseconds());
}
constexpr inline Time operator-(const Time &lhs, const Duration &rhs) {
  return Time(lhs.Microseconds() - rhs.Microseconds());
}
constexpr inline Duration operator-(const Time &lhs, const Time &rhs) {
  return Duration(lhs.Microseconds() - rhs.Microseconds());
}

inline Duration Duration::Since(const Time &t) { return Time::Now() - t; }

inline Duration Duration::Until(const Time &t) { return t - Time::Now(); }

}  // namespace junction
