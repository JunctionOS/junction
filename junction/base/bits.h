// bits.h - useful bit tricks

#pragma once

extern "C" {
#include <base/assert.h>
}

#include <bit>
#include <type_traits>

namespace junction {

// AlignUp aligns the value up to a power of two alignment
template <typename T>
constexpr T AlignUp(T val,
                    size_t align) noexcept requires std::is_unsigned_v<T> {
  assert(std::has_single_bit(align));
  return T((val + (T(align) - 1)) & ~T(align - 1));
}

// AlignDown aligns the value down to a power of two alignment
template <typename T>
constexpr T AlignDown(T val,
                      size_t align) noexcept requires std::is_unsigned_v<T> {
  assert(std::has_single_bit(align));
  return T(val & ~T(align - 1));
}

// DivideUp divides a dividend by a divisor, but rounds up to the next integer
template <typename T>
constexpr T DivideUp(T dividend,
                     T divisor) noexcept requires std::is_integral_v<T> {
  return (dividend + divisor - 1) / divisor;
}

}  // namespace junction
