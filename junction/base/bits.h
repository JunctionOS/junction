// bits.h - useful bit tricks

#pragma once

extern "C" {
#include <base/assert.h>
}

#include <bit>
#include <type_traits>

namespace junction {

// align_up aligns the value up to a power of two alignment
template <typename T>
constexpr T align_up(T val,
                     size_t align) noexcept requires std::is_unsigned_v<T> {
  assert(std::has_single_bit(align));
  return T((val + (T(align) - 1)) & ~T(align - 1));
}

// align_down aligns the value down to a power of two alignment
template <typename T>
constexpr T align_down(T val,
                       size_t align) noexcept requires std::is_unsigned_v<T> {
  assert(std::has_single_bit(align));
  return T(val & ~T(align - 1));
}

// div_up divides a dividend by a divisor, but rounds up to the next integer
template <typename T>
constexpr T div_up(T dividend,
                   T divisor) noexcept requires std::is_integral_v<T> {
  return (dividend + divisor - 1) / divisor;
}

}  // namespace junction
