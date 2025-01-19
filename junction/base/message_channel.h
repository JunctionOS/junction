// message_channel.h - a lock-free FIFO of messages for a single producer and
// consumer

#pragma once

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <span>
#include <vector>

#include "junction/base/error.h"
#include "junction/snapshot/cereal.h"

namespace junction {

template <typename T>
struct Message {
  uint64_t flags{0};
  T aux_data;
  std::vector<std::byte> data;
  template <class Archive>
  void serialize(Archive& ar) {
    ar(flags, aux_data, data);
  }
};

template <>
struct Message<void> {
  uint64_t flags{0};
  std::vector<std::byte> data;
  template <class Archive>
  void serialize(Archive& ar) {
    ar(flags, data);
  }
};

template <typename T>
class MessageChannel {
 public:
  MessageChannel() noexcept = default;
  explicit MessageChannel(size_t size) noexcept
      : size_(std::bit_ceil(std::max(size, size_t{1}))),
        mask_(size_ - 1),
        msgs_(size_) {}
  ~MessageChannel() = default;

  // disable copy and move.
  MessageChannel(const MessageChannel&) = delete;
  MessageChannel& operator=(const MessageChannel&) = delete;
  MessageChannel(MessageChannel&& c) = delete;
  MessageChannel& operator=(MessageChannel&& c) = delete;

  // Returns true if the channel is empty. Should only be called by the reader.
  [[nodiscard]] bool is_empty() const;
  // Returns true if the channel is full. Should only be called by the writer.
  [[nodiscard]] bool is_full() const;
  // Returns the size of this MessageChannel
  [[nodiscard]] size_t get_size() const { return size_; }

  [[nodiscard]] static constexpr bool has_aux() { return !std::is_void_v<T>; }

  // Reads bytes out of the channel. May return less than the bytes available.
  Status<size_t> Read(std::span<std::byte> buf, T* aux_out = nullptr,
                      bool peek = false);

  Status<size_t> Read(std::span<std::byte> buf, bool peek = false) {
    return Read(buf, nullptr, false);
  }

  // Writes bytes in to the channel.
  Status<size_t> Write(std::span<const std::byte> buf, T* aux_in = nullptr);
  Status<size_t> Readv(std::span<iovec> iov, bool peek, T* aux_out = nullptr);
  Status<size_t> Writev(std::span<iovec> iov, T* aux_in = nullptr);

  template <class Archive>
  void save(Archive& ar) const {
    size_t nr_msg = in_ - out_;
    ar(nr_msg);
    for (size_t cur = out_; cur != in_; cur++) ar(msgs_[cur & mask_]);
  }

  template <class Archive>
  void load(Archive& ar) {
    // Assume we have already been constructed with the proper size.
    ar(in_);
    for (size_t i = 0; i < in_; i++) ar(msgs_[i]);
  }

 private:
  std::atomic_size_t in_{0};
  std::atomic_size_t out_{0};
  const size_t size_;
  const size_t mask_;
  std::vector<Message<T>> msgs_;
};

template <typename T>
inline bool MessageChannel<T>::is_empty() const {
  return in_.load(std::memory_order_acquire) ==
         out_.load(std::memory_order_relaxed);
}

template <typename T>
inline bool MessageChannel<T>::is_full() const {
  return in_.load(std::memory_order_relaxed) -
             out_.load(std::memory_order_acquire) >=
         size_;
}

template <typename T>
inline Status<size_t> MessageChannel<T>::Read(std::span<std::byte> buf,
                                              T* aux_out, bool peek) {
  size_t in = in_.load(std::memory_order_acquire);
  size_t out = out_.load(std::memory_order_relaxed);

  if (in == out) return MakeError(EAGAIN);

  Message<T>& src_msg = msgs_[out & mask_];
  size_t to_copy = std::min(buf.size(), src_msg.data.size());
  std::copy_n(std::begin(src_msg.data), to_copy, buf.begin());

  if constexpr (has_aux())
    if (aux_out) *aux_out = src_msg.aux_data;

  if (!peek) {
    out_.store(out + 1, std::memory_order_release);
    src_msg.data.clear();
  }
  return to_copy;
}

template <typename T>
inline Status<size_t> MessageChannel<T>::Write(std::span<const std::byte> buf,
                                               T* aux_in) {
  size_t in = in_.load(std::memory_order_relaxed);
  size_t out = out_.load(std::memory_order_acquire);

  assert(buf.size() > 0);

  if (in - out >= size_) return MakeError(EAGAIN);
  Message<T>& dst_msg = msgs_[in & mask_];
  dst_msg.data.assign(buf.begin(), buf.end());

  if constexpr (has_aux())
    if (aux_in) dst_msg.aux_data = *aux_in;

  in_.store(in + 1, std::memory_order_release);
  return buf.size();
}

template <typename T>
inline Status<size_t> MessageChannel<T>::Readv(std::span<iovec> iov, bool peek,
                                               T* aux_out) {
  size_t in = in_.load(std::memory_order_acquire);
  size_t out = out_.load(std::memory_order_relaxed);

  if (in == out) return MakeError(EAGAIN);

  Message<T>& src_msg = msgs_[out & mask_];
  if (!iov.size()) return MakeError(EINVAL);
  size_t read = GenericReadv(src_msg.data, iov);

  if constexpr (has_aux())
    if (aux_out) *aux_out = src_msg.aux_data;

  if (!peek) {
    out_.store(out + 1, std::memory_order_release);
    src_msg.data.clear();
  }
  return read;
}

template <typename T>
inline Status<size_t> MessageChannel<T>::Writev(std::span<iovec> iov,
                                                T* aux_in) {
  size_t in = in_.load(std::memory_order_relaxed);
  size_t out = out_.load(std::memory_order_acquire);

  if (in - out >= size_) return MakeError(EAGAIN);

  Message<T>& dst_msg = msgs_[in & mask_];

  size_t msg_len = SumIOV(iov);
  if (unlikely(msg_len == 0)) return MakeError(EINVAL);
  dst_msg.data.resize(msg_len);
  GenericWritev(iov, dst_msg.data);
  if constexpr (has_aux())
    if (aux_in) dst_msg.aux_data = *aux_in;
  in_.store(in + 1, std::memory_order_release);
  return dst_msg.data.size();
}

}  // namespace junction
