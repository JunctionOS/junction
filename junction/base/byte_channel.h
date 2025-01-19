// byte_channel.h - a lock-free FIFO of bytes for a single reader & writer

#pragma once

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <span>
#include <vector>

#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/snapshot/cereal.h"

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
  // Returns the size of this ByteChannel
  [[nodiscard]] size_t get_size() const { return size_; }
  [[nodiscard]] size_t get_readable_bytes() const;

  // Reads bytes out of the channel. May return less than the bytes available.
  Status<size_t> Read(std::span<std::byte> buf, bool peek = false);
  // Writes bytes in to the channel. May return less than the bytes available.
  Status<size_t> Write(std::span<const std::byte> buf);
  Status<size_t> Readv(std::span<iovec> iov, bool peek);
  Status<size_t> Writev(std::span<const iovec> iov);

  template <class Archive>
  void save(Archive& ar) const {
    size_t sz = in_ - out_;

    // Data may wrap around, so we might serialize two segments
    size_t seg_1 = std::min(size_ - (out_ & mask_), sz);
    size_t seg_2 = sz - seg_1;

    // save size_ and actual data len
    ar(seg_1, seg_2);
    if (seg_1) ar(cereal::binary_data(buf_.data() + (out_ & mask_), seg_1));
    if (seg_2) ar(cereal::binary_data(buf_.data(), seg_2));
  }

  template <class Archive>
  void load(Archive& ar) {
    // Assume we have already been constructed with the proper size.
    size_t seg_1, seg_2;
    ar(seg_1, seg_2);
    if (seg_1) ar(cereal::binary_data(buf_.data(), seg_1));
    if (seg_2) ar(cereal::binary_data(buf_.data() + seg_1, seg_2));
    in_ = seg_1 + seg_2;
  }

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

[[nodiscard]] inline size_t ByteChannel::get_readable_bytes() const {
  return in_.load(std::memory_order_acquire) -
         out_.load(std::memory_order_relaxed);
}

inline Status<size_t> ByteChannel::Read(std::span<std::byte> buf, bool peek) {
  size_t in = in_.load(std::memory_order_acquire);
  size_t out = out_.load(std::memory_order_relaxed);
  size_t n = std::min(in - out, buf.size());
  if (n == 0) return MakeError(EAGAIN);

  // Handle the case where the buffer wraps around.
  size_t n_to_end = size_ - (out & mask_);
  if (n > n_to_end) {
    std::copy_n(std::begin(buf_) + (out & mask_), n_to_end, buf.begin());
    std::copy_n(std::begin(buf_), n - n_to_end, buf.begin() + n_to_end);
    if (!peek) out_.store(out + n, std::memory_order_release);
    return n;
  }

  // Otherwise do a single copy.
  std::copy_n(std::begin(buf_) + (out & mask_), n, buf.begin());
  if (!peek) out_.store(out + n, std::memory_order_release);
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

inline Status<size_t> ByteChannel::Readv(std::span<iovec> iov, bool peek) {
  size_t in = in_.load(std::memory_order_acquire);
  size_t out = out_.load(std::memory_order_relaxed);
  size_t n = in - out;
  if (n == 0) return MakeError(EAGAIN);

  size_t copied;
  iovec src[2];
  src[0].iov_base = buf_.data() + (out & mask_);

  // Handle the case where the buffer wraps around.
  size_t n_to_end = size_ - (out & mask_);
  if (n > n_to_end) {
    src[0].iov_len = n_to_end;
    src[1].iov_base = buf_.data();
    src[1].iov_len = n - n_to_end;
    copied = GenericCopyv(std::span{src, 2}, iov);
  } else {
    src[0].iov_len = n;
    copied = GenericCopyv(std::span{src, 1}, iov);
  }

  if (!peek) out_.store(out + copied, std::memory_order_release);
  return copied;
}

inline Status<size_t> ByteChannel::Writev(std::span<const iovec> iov) {
  size_t in = in_.load(std::memory_order_relaxed);
  size_t out = out_.load(std::memory_order_acquire);
  size_t n = size_ - (in - out);
  if (n == 0) return MakeError(EAGAIN);

  size_t copied;
  iovec src[2];
  src[0].iov_base = buf_.data() + (in & mask_);

  // Handle the case where the buffer wraps around.
  size_t n_to_end = size_ - (in & mask_);
  if (n > n_to_end) {
    src[0].iov_len = n_to_end;
    src[1].iov_base = buf_.data();
    src[1].iov_len = n - n_to_end;
    copied = GenericCopyv(iov, std::span{src, 2});
  } else {
    src[0].iov_len = n;
    copied = GenericCopyv(iov, std::span{src, 1});
  }

  in_.store(in + copied, std::memory_order_release);
  return copied;
}

}  // namespace junction
