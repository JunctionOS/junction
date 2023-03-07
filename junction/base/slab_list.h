#pragma once

#include <cmath>
#include <iterator>
#include <stdexcept>

namespace junction {

template <size_t BlockSize, size_t MaxBlocks>
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

  SlabList() {
    for (size_t i = 0; i < MaxBlocks; i++) {
      block_ptrs_[i] = nullptr;
    }
  }

  SlabList(const size_t size) : SlabList() { Resize(size); }

  // Adds or removes blocks to reach the target size.
  void Resize(const size_t size) {
    if (size > max_size()) {
      throw std::length_error("Exceeds MaxSize");
    }
    if (size < 0) {
      throw std::length_error("Negative size");
    }

    const size_t blocks_needed =
        size < BlockSize ? 1 : std::ceil(static_cast<float>(size) / BlockSize);
    if (blocks_needed > n_blocks_in_use_) {
      // Add blocks
      const size_t delta = blocks_needed - n_blocks_in_use_;
      for (size_t i = 0; i < delta; i++) {
        void* p = malloc(BlockSize);
        if (!p) throw std::bad_alloc();
        block_ptrs_[i + n_blocks_in_use_] = p;
      }
    } else {
      // Remove blocks
      const size_t delta = n_blocks_in_use_ - blocks_needed;
      for (size_t i = 0; i < delta; i++) {
        const size_t idx = n_blocks_in_use_ - i;
        free(block_ptrs_[idx]);
        block_ptrs_[idx] = nullptr;
      }
    }
    n_blocks_in_use_ = blocks_needed;
    size_ = size;
  }

  std::byte& operator[](int idx) { return *(get_ptr(idx)); }

  std::byte* get_ptr(size_t idx) {
    // Note: No bounds checks are performed.
    const size_t block = std::floor(static_cast<float>(idx) / BlockSize);
    return reinterpret_cast<std::byte*>(block_ptrs_[block]) + (idx % BlockSize);
  }

  size_t size() const { return size_; }

  size_t max_size() const {
    static size_t MaxSize = BlockSize * MaxBlocks;
    return MaxSize;
  }

 private:
  void* block_ptrs_[MaxBlocks];
  size_t size_{0};
  size_t n_blocks_in_use_{0};
};

}  // namespace junction
