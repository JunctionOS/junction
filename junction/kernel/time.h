// time.h - support for time keeping functions

#pragma once

extern "C" {
#include <sys/time.h>
}

#include "junction/bindings/timer.h"

namespace junction {

// Converts a Linux timeval into microseconds
constexpr uint64_t timeval_to_us(const timeval &tv) {
  return tv.tv_sec * rt::kSeconds + tv.tv_usec;
}

// Converts microseconds into a Linux timeval
constexpr timeval us_to_timeval(uint64_t us) {
  return timeval{.tv_sec = static_cast<time_t>(us / rt::kSeconds),
                 .tv_usec = static_cast<suseconds_t>(us % rt::kSeconds)};
}

// Converts a Linux timespec into microseconds
constexpr uint64_t timespec_to_us(const timespec &ts) {
  return ts.tv_sec * rt::kSeconds + ts.tv_nsec / 1000;
}

// Converts microseconds into a Linux timespec
constexpr timespec us_to_timespec(uint64_t us) {
  return timespec{.tv_sec = static_cast<time_t>(us / rt::kSeconds),
                  .tv_nsec = static_cast<long>((us % rt::kSeconds) * 1000)};
}

}  // namespace junction
