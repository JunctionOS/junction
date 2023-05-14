// bitmap.h - a collection of bit-based datastructures

#pragma once

#include <algorithm>
#include <limits>
#include <optional>
#include <vector>

#include "junction/base/bits.h"

namespace junction {

namespace detail {

inline constexpr size_t kBitsPerLong = sizeof(unsigned long) * kBitsPerByte;
constexpr size_t get_idx(size_t pos) { return pos / kBitsPerLong; }
constexpr size_t get_shift(size_t pos) { return pos % kBitsPerLong; }
constexpr size_t get_size(size_t n) {
  return DivideUp(n, sizeof(unsigned long));
}

}  // namespace detail

// bitmap is a statically-sized set of bits
template <size_t N>
class bitmap {
 public:
  bitmap() noexcept = default;
  ~bitmap() = default;

  // size returns the number of bits
  [[nodiscard]] size_t size() const { return N; }

  // test returns true if the bit @pos is set.
  [[nodiscard]] bool test(size_t pos) const {
    assert(pos < N);
    return (bits_[detail::get_idx(pos)] & (1UL << detail::get_shift(pos))) != 0;
  }

  // sets the bit at @pos
  void set(size_t pos) {
    assert(pos < N);
    bits_[detail::get_idx(pos)] |= (1UL << detail::get_shift(pos));
  }

  // sets all bits
  void set() {
    std::fill(bits_.begin(), bits_.end(),
              std::numeric_limits<unsigned long>::max());
  }

  // clears the bit at @pos
  void clear(size_t pos) {
    assert(pos < N);
    bits_[detail::get_idx(pos)] &= ~(1UL << detail::get_shift(pos));
  }

  // clears all bits
  void clear() { std::fill(bits_.begin(), bits_.end(), 0); }

  // all checks if all bits are set
  bool all() const {
    for (const unsigned long val : bits_)
      if (val != std::numeric_limits<unsigned long>::max()) return false;
    return true;
  }

  // any checks if any bit is set
  bool any() const {
    for (const unsigned long val : bits_)
      if (val != 0) return true;
    return false;
  }

  // none checks if no bit is set
  bool none() const {
    for (const unsigned long val : bits_)
      if (val != 0) return false;
    return true;
  }

  // count returns the number of set bits
  size_t count() const {
    size_t count = 0;
    for (const unsigned long val : bits_) count += __builtin_popcount(val);
    return count;
  }

  // find_next_set finds the next set bit starting at @pos, if it exists
  [[nodiscard]] std::optional<size_t> find_next_set(size_t pos) const {
    assert(pos < N);
    return find_next<false>(pos);
  }

  // find_next_clear finds the next clear bit starting at @pos, if it exists
  [[nodiscard]] std::optional<size_t> find_next_clear(size_t pos) const {
    assert(pos < N);
    return find_next<true>(pos);
  }

 private:
  template <bool Invert>
  std::optional<size_t> find_next(size_t pos) const;

  unsigned long bits_[detail::get_size(N)] = {0};
};

template <size_t N>
template <bool Invert>
std::optional<size_t> bitmap<N>::find_next(size_t pos) const {
  unsigned long mask = ~((1UL << detail::get_shift(pos)) - 1);
  for (size_t i = AlignDown(pos, detail::kBitsPerLong); i < N;
       i += detail::kBitsPerLong) {
    unsigned long val = bits_[detail::get_idx(i)];
    if constexpr (Invert) val = ~val;
    val &= mask;
    val = __builtin_ffsl(val);
    if (val == 0) {
      mask = ~0UL;
      continue;
    }
    size_t ret = i + val - 1;
    if constexpr (N % detail::kBitsPerLong != 0) {
      if (ret >= N) return {};
    }
    return ret;
  }

  return {};
}

// dynamic_bitmap is a dynamically-sized set of bits
class dynamic_bitmap {
 public:
  dynamic_bitmap() noexcept = default;
  dynamic_bitmap(size_t n) : size_(n), bits_(std::vector<unsigned long>(n)) {}
  ~dynamic_bitmap() = default;

  // Move support
  dynamic_bitmap(dynamic_bitmap &&b) noexcept
      : size_(b.size_), bits_(std::move(b.bits_)) {}
  dynamic_bitmap &operator=(dynamic_bitmap &&b) noexcept {
    size_ = b.size_;
    bits_ = std::move(b.bits_);
    return *this;
  }

  // Copy support
  dynamic_bitmap(const dynamic_bitmap &b) = default;
  dynamic_bitmap &operator=(const dynamic_bitmap &b) = default;

  // size returns the number of bits
  [[nodiscard]] size_t size() const { return size_; }

  // test returns true if the bit @pos is set
  [[nodiscard]] bool test(size_t pos) const {
    assert(pos < size_);
    return (bits_[detail::get_idx(pos)] & (1UL << detail::get_shift(pos))) != 0;
  }

  // resize the bitmap to a new number of bits
  void resize(size_t n) {
    bits_.resize(DivideUp(n, sizeof(unsigned long)));
    size_ = n;
  }

  // sets the bit at @pos
  void set(size_t pos) {
    assert(pos < size_);
    bits_[detail::get_idx(pos)] |= (1UL << detail::get_shift(pos));
  }

  // sets all bits
  void set() {
    std::fill(bits_.begin(), bits_.end(),
              std::numeric_limits<unsigned long>::max());
  }

  // clears the bit at @pos
  void clear(size_t pos) {
    assert(pos < size_);
    bits_[detail::get_idx(pos)] &= ~(1UL << detail::get_shift(pos));
  }

  // clears all bits
  void clear() { std::fill(bits_.begin(), bits_.end(), 0); }

  // all checks if all bits are set
  bool all() const {
    for (const unsigned long val : bits_)
      if (val != std::numeric_limits<unsigned long>::max()) return false;
    return true;
  }

  // any checks if any bit is set
  bool any() const {
    for (const unsigned long val : bits_)
      if (val != 0) return true;
    return false;
  }

  // none checks if no bit is set
  bool none() const {
    for (const unsigned long val : bits_)
      if (val != 0) return false;
    return true;
  }

  // count returns the number of set bits
  size_t count() const {
    size_t count = 0;
    for (const unsigned long val : bits_) count += __builtin_popcount(val);
    return count;
  }

  // find_next_set finds the next set bit starting at @pos, if it exists
  [[nodiscard]] std::optional<size_t> find_next_set(size_t pos) const {
    assert(pos < size_);
    return find_next<false>(pos);
  }

  // find_next_clear finds the next clear bit starting at @pos, if it exists
  [[nodiscard]] std::optional<size_t> find_next_clear(size_t pos) const {
    assert(pos < size_);
    return find_next<true>(pos);
  }

 private:
  template <bool Invert>
  std::optional<size_t> find_next(size_t pos) const;

  size_t size_{0};
  std::vector<unsigned long> bits_;
};

template <bool Invert>
std::optional<size_t> dynamic_bitmap::find_next(size_t pos) const {
  unsigned long mask = ~((1UL << detail::get_shift(pos)) - 1);
  for (size_t i = AlignDown(pos, detail::kBitsPerLong); i < size();
       i += detail::kBitsPerLong) {
    unsigned long val = bits_[detail::get_idx(i)];
    if constexpr (Invert) val = ~val;
    val &= mask;
    val = __builtin_ffsl(val);
    if (val == 0) {
      mask = ~0UL;
      continue;
    }
    size_t ret = i + val - 1;
    if (ret >= size()) return {};
    return ret;
  }

  return {};
}

// IterableBitmap is the concept of a bitmap that can find set and cleared bits.
template <typename T>
concept IterableBitmap = requires(T t) {
  { t.find_next_set(size_t()) } -> std::same_as<std::optional<size_t>>;
  { t.find_next_clear(size_t()) } -> std::same_as<std::optional<size_t>>;
};

// for_each_set_bit invokes a function for each bit that is set.
template <IterableBitmap B, typename F>
void for_each_set_bit(B bitmap, F func) {
  std::optional<size_t> idx = bitmap.find_next_set(0);
  while (idx) {
    func(*idx);
    idx = bitmap.find_next_set(*idx + 1);
  }
}

// for_each_clear_bit invokes a function for each bit that is cleared.
template <IterableBitmap B, typename F>
void for_each_clear_bit(B bitmap, F func) {
  std::optional<size_t> idx = bitmap.find_next_clear(0);
  while (idx) {
    func(*idx);
    idx = bitmap.find_next_clear(*idx + 1);
  }
}

}  // namespace junction
