// time.h - utilities for measuring and representing time

#pragma once

extern "C" {
#include <base/time.h>
#include <sys/time.h>
}

#include <string>

#include "junction/base/error.h"

namespace junction {

inline constexpr uint64_t kMilliseconds = 1000;
inline constexpr uint64_t kSeconds = 1000000;

namespace detail {

// Microtime returns microseconds since the launch of the runtime.
inline uint64_t MicroTime() { return microtime(); }

// Converts a Linux timeval into microseconds
constexpr inline uint64_t timeval_to_us(const timeval &tv) {
  return tv.tv_sec * kSeconds + tv.tv_usec;
}

// Converts microseconds into a Linux timeval
constexpr inline timeval us_to_timeval(uint64_t us) {
  return timeval{.tv_sec = static_cast<time_t>(us / kSeconds),
                 .tv_usec = static_cast<suseconds_t>(us % kSeconds)};
}

// Converts a Linux timespec into microseconds
constexpr inline uint64_t timespec_to_us(const timespec &ts) {
  return ts.tv_sec * kSeconds + ts.tv_nsec / 1000;
}

// Converts microseconds into a Linux timespec
constexpr inline timespec us_to_timespec(uint64_t us) {
  return timespec{.tv_sec = static_cast<time_t>(us / kSeconds),
                  .tv_nsec = static_cast<long>((us % kSeconds) * 1000)};
}

}  // namespace detail

class Time;

// Duration specifies an interval of time.
class Duration {
 public:
  constexpr Duration() = default;
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
  // Timespec converts the duration to a Linux timespec. Behavior is undefined
  // if the duration is negative.
  constexpr timespec Timespec() const {
    return detail::us_to_timespec(duration_);
  }

  // Microseconds converts the duration into microseconds (can be negative).
  constexpr int64_t Microseconds() const { return duration_; }
  // Milliseconds converts the duration into milliseconds (can be negative).
  constexpr int64_t Milliseconds() const { return duration_ / kMilliseconds; }
  // Seconds converts the duration into seconds (can be negative).
  constexpr double Seconds() const {
    return static_cast<double>(duration_) / static_cast<double>(kSeconds);
  }

  // IsZero checks if the duration is zero.
  constexpr bool IsZero() const { return duration_ == 0; }

  // ToString converts to a string representation.
  //
  // TODO(amb): Make the formatting nicer.
  // Currently displayed in seconds (e.g., 5500 us would be '5.5s')
  std::string ToString() const { return std::to_string(Seconds()) + "s"; }

  // Enable comparisons
  constexpr auto operator<=>(const Duration &) const = default;

 private:
  int64_t duration_;
};

// Literals representing different time durations
//
// Example usage:
//  Sleep(10_ms);
constexpr Duration operator""_s(unsigned long long s) {
  return Duration(s * kSeconds);
}
constexpr Duration operator""_ms(unsigned long long ms) {
  return Duration(ms * kMilliseconds);
}
constexpr Duration operator""_us(unsigned long long us) { return Duration(us); }

// Time specifies a point in time.
class Time {
 public:
  constexpr Time() = default;
  constexpr explicit Time(uint64_t us) : time_(us) {}
  constexpr explicit Time(const timeval &tv)
      : time_(detail::timeval_to_us(tv)) {}
  constexpr explicit Time(const timespec &ts)
      : time_(detail::timespec_to_us(ts)) {}
  constexpr ~Time() = default;

  // Time object from an absolute unix time timespec
  static Time FromUnixTime(timespec ts) {
    return FromUnixTime(detail::timespec_to_us(ts));
  }

  // Time object from an absolute unix time timeval
  static Time FromUnixTime(timeval tv) {
    return FromUnixTime(detail::timeval_to_us(tv));
  }

  // Now gets the current time.
  static Time Now() { return Time(detail::MicroTime()); }

  // Timeval converts the time to a Linux timeval.
  constexpr timeval Timeval() const { return detail::us_to_timeval(time_); }
  // Timespec converts the time to a Linux timespec.
  constexpr timespec Timespec() const { return detail::us_to_timespec(time_); }

  // Microseconds converts the time into microseconds.
  constexpr uint64_t Microseconds() const { return time_; }
  // Milliseconds converts the time into milliseconds.
  constexpr uint64_t Milliseconds() const { return time_ / kMilliseconds; }
  // Seconds converts the time into seconds.
  constexpr double Seconds() const {
    return static_cast<double>(time_) / static_cast<double>(kSeconds);
  }

  // ToString converts to a string representation.
  //
  // TODO(amb): Make the formatting nicer.
  // Currently displayed in seconds (e.g., 5500 us would be '5.5s')
  std::string ToString() const { return std::to_string(Seconds()) + "s"; }

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

  static void SetStartTimeUnix(Time t) { start_time_unix = t; }

  // converts a Time instance to a unix time timeval.
  constexpr timeval TimevalUnixTime() const {
    return detail::us_to_timeval(time_ + start_time_unix.Microseconds());
  }
  // converts a Time instance to a unix time timespec.
  constexpr timespec TimespecUnixTime() const {
    return detail::us_to_timespec(time_ + start_time_unix.Microseconds());
  }

 private:
  static Time FromUnixTime(uint64_t micros) {
    return Time(micros - start_time_unix.Microseconds());
  }

  uint64_t time_;
  static Time start_time_unix;
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

Status<void> InitUnixTime();

}  // namespace junction
