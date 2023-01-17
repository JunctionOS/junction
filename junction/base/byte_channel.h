// byte_channel.h - a lock-free FIFO of bytes for a single reader & writer

#pragma once

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <memory>
#include <span>

#include "junction/base/error.h"

namespace junction {

class ByteChannel {
 public:
  ByteChannel() noexcept = default;
  explicit ByteChannel(size_t size) noexcept
      : size_(std::bit_ceil(std::max(size, size_t{1}))),
        mask_(size_ - 1),
        buf_(size_) {}
  ~ByteChannel() = default;

  // disable copy and move.
  ByteChannel(const ByteChannel&) = delete;
  ByteChannel& operator=(const ByteChannel&) = delete;
  ByteChannel(ByteChannel&& c) = delete;
  ByteChannel& operator=(ByteChannel&& c) = delete;

  // Returns true if the channel is empty. Should only be called by the reader.
  [[nodiscard]] bool is_empty() const;
  // Returns true if the channel is full. Should only be called by the writer.
  [[nodiscard]] bool is_full() const;
  // Returns true if the byte channel is initialized and usable.
  [[nodiscard]] bool is_valid() const { return !buf_.empty(); }

  // Reads bytes out of the channel. May return less than the bytes available.
  Status<size_t> Read(std::span<std::byte> buf);
  // Writes bytes in to the channel. May return less than the bytes available.
  Status<size_t> Write(std::span<const std::byte> buf);

 private:
  std::atomic_size_t in_{0};
  std::atomic_size_t out_{0};
  const size_t size_;
  const size_t mask_;
  std::vector<std::byte> buf_;
};

inline bool ByteChannel::is_empty() const {
  return in_.load(std::memory_order_acquire) ==
         out_.load(std::memory_order_relaxed);
}

inline bool ByteChannel::is_full() const {
  return in_.load(std::memory_order_relaxed) -
             out_.load(std::memory_order_acquire) >=
         size_;
}

inline Status<size_t> ByteChannel::Read(std::span<std::byte> buf) {
  size_t in = in_.load(std::memory_order_acquire);
  size_t out = out_.load(std::memory_order_relaxed);
  size_t n = std::min(in - out, buf.size());
  if (n == 0) return MakeError(EAGAIN);

  // Handle the case where the buffer wraps around.
  size_t n_to_end = size_ - (out & mask_);
  if (n > n_to_end) {
    std::copy_n(std::begin(buf_) + (out & mask_), n_to_end, buf.begin());
    std::copy_n(std::begin(buf_), n - n_to_end, buf.begin() + n_to_end);
    out_.store(out + n, std::memory_order_release);
    return n;
  }

  // Otherwise do a single copy.
  std::copy_n(std::begin(buf_) + (out & mask_), n, buf.begin());
  out_.store(out + n, std::memory_order_release);
  return n;
}

inline Status<size_t> ByteChannel::Write(std::span<const std::byte> buf) {
  size_t in = in_.load(std::memory_order_relaxed);
  size_t out = out_.load(std::memory_order_acquire);
  size_t n = std::min(size_ - (in - out), buf.size());
  if (n == 0) return MakeError(EAGAIN);

  // Handle the case where the buffer wraps around.
  size_t n_to_end = size_ - (in & mask_);
  if (n > n_to_end) {
    std::copy_n(buf.begin(), n_to_end, std::begin(buf_) + (in & mask_));
    std::copy_n(buf.begin() + n_to_end, n - n_to_end, std::begin(buf_));
    in_.store(in + n, std::memory_order_release);
    return n;
  }

  // Otherwise do a single copy.
  std::copy_n(buf.begin(), n, std::begin(buf_) + (in & mask_));
  in_.store(in + n, std::memory_order_release);
  return n;
}

}  // namespace junction
