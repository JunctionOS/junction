// bitmap.h - a simple bitmap datastruct (like bitset but using GCC builtins)
// TODO(amb): add missing bitset functions and iterator support when/if needed

#pragma once

#include <optional>

#include "junction/base/bits.h"

namespace junction {

template <size_t N>
class bitmap {
 public:
  bitmap() noexcept = default;
  ~bitmap() = default;

  // size returns the number of bits
  size_t size() const { return N; }

  // test returns true if the bit @pos is set.
  bool test(size_t pos) const {
    return bits_[get_idx(pos)] & (1UL << get_shift(pos)) != 0;
  }

  // sets the bit at @pos
  void set(size_t pos) { bits_[get_idx(pos)] |= (1UL << get_shift(pos)); }

  // clears the bit at @pos
  void reset(size_t pos) { bits_[get_idx(pos)] &= ~(1UL << get_shift(pos)); }

  // find_next_set finds the next set bit starting at @pos, if it exists
  std::optional<size_t> find_next_set(size_t pos) const {
    return find_next<false>(pos);
  }

  // find_next_clear finds the next clear bit starting at @pos, if it exists
  std::optional<size_t> find_next_clear(size_t pos) const {
    return find_next<true>(pos);
  }

 private:
  static constexpr size_t kBitsPerLong = sizeof(unsigned long) * kBitsPerByte;

  constexpr size_t get_idx(size_t pos) const { return pos / kBitsPerLong; }
  constexpr size_t get_shift(size_t pos) const { return pos % kBitsPerLong; }

  template <bool Invert>
  std::optional<size_t> find_next(size_t pos) const;

  unsigned long bits_[DivideUp(N, sizeof(unsigned long))] = {0};
};

template <size_t N>
template <bool Invert>
std::optional<size_t> bitmap<N>::find_next(size_t pos) const {
  // TODO(amb): Could specialize this for N <= kBitsPerByte.
  unsigned long mask = ~((1UL << get_shift(pos)) - 1);
  for (size_t i = AlignDown(pos, kBitsPerLong); i < N; i += kBitsPerLong) {
    unsigned long val = bits_[get_idx(i)];
    if constexpr (Invert) val = ~val;
    val &= mask;
    val = __builtin_ffsl(val);
    if (val == 0) {
      mask = ~0UL;
      continue;
    }
    size_t ret = i + val - 1;
    if constexpr (N % kBitsPerLong != 0) {
      if (ret >= N) return {};
    }
    return ret;
  }

  return {};
}

}  // namespace junction
