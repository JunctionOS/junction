#pragma once

#include <cmath>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <vector>

#include "junction/base/bits.h"

namespace junction {

template <size_t BlockSize>
class SlabList {
 public:
  struct const_iterator;

  struct iterator {
    using iterator_category = std::random_access_iterator_tag;
    using difference_type = ssize_t;
    using value_type = std::byte;
    using pointer = std::byte*;
    using reference = std::byte&;

    iterator() {}
    explicit iterator(SlabList* sl, size_t idx) : sl_(sl), idx_(idx) {}
    reference operator*() const { return *(sl_->get_ptr(idx_)); }
    pointer operator->() const { return sl_->get_ptr(idx_); }

    // Prefix increment
    iterator& operator++() {
      ++idx_;
      return *this;
    }

    // Postfix increment
    iterator operator++(int) {
      iterator tmp = *this;
      ++idx_;
      return tmp;
    }

    // Increment
    iterator operator+(difference_type i) { return iterator(sl_, idx_ + i); }
    difference_type operator+(const iterator other) const {
      return idx_ + other;
    }

    // Prefix decrement
    iterator& operator--() {
      --idx_;
      return *this;
    }

    // Postfix decrement
    iterator operator--(int) {
      iterator tmp = *this;
      --idx_;
      return tmp;
    }

    friend bool operator==(const iterator& a, const iterator& b) {
      return a.idx_ == b.idx_;
    };
    friend bool operator!=(const iterator& a, const iterator& b) {
      return a.idx_ != b.idx_;
    };
    friend size_t operator-(const iterator& a, const iterator& b) {
      return a.idx_ - b.idx_;
    };
    friend bool operator<(const iterator& a, const iterator& b) {
      return a.idx_ < b.idx_;
    };
    friend const_iterator;

   private:
    SlabList* sl_{nullptr};
    size_t idx_{-1};
  };

  struct const_iterator {
    using iterator_category = std::random_access_iterator_tag;
    using difference_type = ssize_t;
    using value_type = const std::byte;
    using pointer = const std::byte*;
    using reference = const std::byte&;

    const_iterator() {}
    explicit const_iterator(SlabList* sl, size_t idx) : sl_(sl), idx_(idx) {}
    const_iterator(const const_iterator& it) : sl_(it.sl_), idx_(it.idx_) {}
    reference operator*() const { return (*sl_)[idx_]; }
    pointer operator->() const { return sl_->get_ptr(idx_); }

    // Prefix increment
    const_iterator& operator++() {
      idx_++;
      return *this;
    }

    // Postfix increment
    const_iterator operator++(int) {
      const_iterator tmp = *this;
      ++idx_;
      return tmp;
    }

    // Increment
    const_iterator operator+(difference_type i) {
      return const_iterator(sl_, idx_ + i);
    }
    difference_type operator+(const const_iterator other) const {
      return idx_ + other;
    }

    // Prefix decrement
    const_iterator& operator--() {
      idx_--;
      return *this;
    }

    // Postfix decrement
    const_iterator operator--(int) {
      const_iterator tmp = *this;
      --idx_;
      return tmp;
    }

    friend bool operator==(const const_iterator& a, const const_iterator& b) {
      return a.idx_ == b.idx_;
    };
    friend bool operator!=(const const_iterator& a, const const_iterator& b) {
      return a.idx_ != b.idx_;
    };
    friend size_t operator-(const const_iterator& a, const const_iterator& b) {
      return a.idx_ - b.idx_;
    };

   private:
    SlabList* sl_{nullptr};
    size_t idx_{-1};
  };

  iterator begin() { return iterator(this, 0); }
  iterator end() { return iterator(this, size_); }
  const_iterator cbegin() { return const_iterator(this, 0); }
  const_iterator cend() { return const_iterator(this, size_); }

  SlabList() = default;

  SlabList(const size_t size) : SlabList() { Resize(size); }

  // Adds or removes blocks to reach the target size.
  void Resize(const size_t size) {
    const size_t blocks_needed = DivideUp(size, BlockSize);
    block_ptrs_.resize(blocks_needed);

    // Add blocks if needed
    for (size_t i = n_blocks_in_use_; i < blocks_needed; i++)
      block_ptrs_[i].reset(new char[BlockSize]);

    n_blocks_in_use_ = blocks_needed;
    size_ = size;
  }

  std::byte& operator[](int idx) { return *(get_ptr(idx)); }

  std::byte* get_ptr(size_t idx) {
    // Note: No bounds checks are performed.
    const size_t block = idx / BlockSize;
    return reinterpret_cast<std::byte*>(block_ptrs_[block].get()) +
           (idx % BlockSize);
  }

  size_t size() const { return size_; }

 private:
  std::vector<std::unique_ptr<char[]>> block_ptrs_;
  size_t size_{0};
  size_t n_blocks_in_use_{0};
};

}  // namespace junction
