// uid.h - tools for generating unique IDs

#pragma once

#include "junction/base/bitmap.h"

namespace junction {

template <size_t N>
class UIDGenerator {
 public:
  UIDGenerator() = default;
  explicit UIDGenerator(size_t pos) : pos_(pos) {}
  ~UIDGenerator() = default;

  // Generate a new unique ID.
  std::optional<size_t> operator()() {
    std::optional<size_t> next = get_next();
    if (unlikely(!next && pos_ > 0)) {
      pos_ = 0;
      return get_next();
    }
    return next;
  }

  // Relinquish a unique ID, allowing it to be used again.
  void Release(size_t pos) { bits_.clear(pos - 1); }

 private:
  std::optional<size_t> get_next() {
    std::optional<size_t> next = bits_.find_next_clear(pos_);
    if (next) {
      bits_.set(*next);
      pos_ = (*next + 1) % N;
      return *next + 1;
    }
    return next;
  }

  size_t pos_{0};
  bitmap<N> bits_;
};

}  // namespace junction
