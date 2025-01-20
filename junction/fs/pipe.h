// pipe.h

#include <atomic>
#include <memory>

#include "junction/base/byte_channel.h"
#include "junction/base/message_channel.h"
#include "junction/bindings/log.h"
#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

namespace junction {

namespace {

// This guard is a no-op if the template parameter is false.
template <bool GuardEnabled>
class ConditionalSpinGuard {
 public:
  [[nodiscard]] explicit ConditionalSpinGuard(rt::Spin &lock) noexcept
      : lock_(lock) {
    if constexpr (GuardEnabled) lock_.Lock();
  }
  ~ConditionalSpinGuard() {
    if constexpr (GuardEnabled) lock_.Unlock();
  }

  ConditionalSpinGuard(ConditionalSpinGuard &&) = delete;
  ConditionalSpinGuard &operator=(ConditionalSpinGuard &&) = delete;
  ConditionalSpinGuard(const ConditionalSpinGuard &) = delete;
  ConditionalSpinGuard &operator=(const ConditionalSpinGuard &) = delete;

 private:
  rt::Spin &lock_;
};

template <class Channel, bool MultiWriter>
class WaitableChannel {
 public:
  explicit WaitableChannel(size_t size) noexcept : chan_(size) {}
  ~WaitableChannel() = default;

  template <typename Callable>
  inline Status<size_t> DoRead(bool nonblocking, Callable &&func) {
    size_t n;
    while (true) {
      // Read from the channel (without locking).
      Status<size_t> ret = func(chan_);
      if (ret) {
        n = *ret;
        break;
      }

      // Return if can't block.
      if (nonblocking) {
        if (writer_is_closed() && chan_.is_empty()) return 0;
        return MakeError(EAGAIN);
      }

      // Channel is empty, block and wait.
      assert(ret.error() == EAGAIN);
      rt::SpinGuard guard(lock_);
      bool signaled = !rt::WaitInterruptible(lock_, read_waker_, [this] {
        return !chan_.is_empty() || writer_is_closed() || reader_is_closed();
      });
      if ((reader_is_closed() || writer_is_closed()) && chan_.is_empty())
        return 0;
      if (signaled) return MakeError(EINTR);
    }

    // Wake the writer and any pollers.
    {
      rt::SpinGuard guard(lock_);
      if (chan_.is_empty() && read_poll_) read_poll_.Clear(kPollIn);
      if (writer_is_closed()) return n;
      if (!chan_.is_full() && write_poll_) {
        write_poll_.Set(kPollOut);
        WakeWriters();
      }
    }
    return n;
  }

  template <typename Callable>
  inline Status<size_t> DoWrite(bool nonblocking, Callable &&func) {
    size_t n;

    ConditionalSpinGuard<MultiWriter> g(lock_);
    while (true) {
      // Write to the channel (without locking).
      Status<size_t> ret = func(chan_);
      if (ret) {
        n = *ret;
        break;
      }

      // Return if can't block.
      if (nonblocking) {
        if (reader_is_closed()) return MakeError(EPIPE);
        return MakeError(EAGAIN);
      }

      // Channel is full, block and wait.
      assert(ret.error() == EAGAIN);
      ConditionalSpinGuard<!MultiWriter> guard(lock_);
      bool signaled = !rt::WaitInterruptible(lock_, write_waker_, [this] {
        return !chan_.is_full() || reader_is_closed() || writer_is_closed();
      });
      if (writer_is_closed() || reader_is_closed()) return MakeError(EPIPE);
      if (signaled) return MakeError(EINTR);
    }

    // Wake the reader and any pollers.
    {
      ConditionalSpinGuard<!MultiWriter> guard(lock_);
      if (chan_.is_full() && write_poll_) write_poll_.Clear(kPollOut);
      if (reader_is_closed()) return MakeError(EPIPE);
      if (!chan_.is_empty() && read_poll_) {
        read_poll_.Set(kPollIn);
        read_waker_.Wake();
      }
    }
    return n;
  }

  Status<size_t> Read(std::span<std::byte> buf, bool nonblocking,
                      bool peek = false) {
    return DoRead(nonblocking,
                  [&](Channel &chan) { return chan.Read(buf, peek); });
  }

  Status<size_t> Readv(std::span<iovec> vec, bool nonblocking,
                       bool peek = false) {
    return DoRead(nonblocking,
                  [&](Channel &chan) { return chan.Readv(vec, peek); });
  }

  Status<size_t> Write(std::span<const std::byte> buf, bool nonblocking) {
    if (buf.size() == 0) return 0;
    return DoWrite(nonblocking, [&](Channel &chan) { return chan.Write(buf); });
  }

  Status<size_t> Writev(std::span<const iovec> vec, bool nonblocking) {
    return DoWrite(nonblocking,
                   [&](Channel &chan) { return chan.Writev(vec); });
  }

  void CloseReader(PollSource *p = nullptr);
  void CloseWriter(PollSource *p = nullptr);

  void AttachReadPoll(PollSource *p) {
    rt::SpinGuard guard(lock_);
    read_poll_.Attach(p);
    if (reader_is_closed()) return;
    if (writer_is_closed())
      read_poll_.Set(kPollHUp);
    else if (!is_empty())
      read_poll_.Set(kPollIn);
  }

  void AttachWritePoll(PollSource *p) {
    rt::SpinGuard guard(lock_);
    write_poll_.Attach(p);
    if (writer_is_closed()) return;
    if (reader_is_closed())
      write_poll_.Set(kPollErr);
    else if (!is_full())
      write_poll_.Set(kPollOut);
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(chan_.get_size(), chan_, reader_closed_, writer_closed_);
  }

  template <class Archive>
  static void load_and_construct(
      Archive &ar,
      cereal::construct<WaitableChannel<Channel, MultiWriter>> &construct) {
    size_t sz;
    ar(sz);
    construct(sz);

    WaitableChannel<Channel, MultiWriter> &p = *construct.ptr();
    ar(p.chan_, p.reader_closed_, p.writer_closed_);
  }

  [[nodiscard]] bool is_empty() const { return chan_.is_empty(); }
  [[nodiscard]] bool is_full() const { return chan_.is_full(); }

 private:
  [[nodiscard]] bool reader_is_closed() const {
    return reader_closed_.load(std::memory_order_acquire);
  }
  [[nodiscard]] bool writer_is_closed() const {
    return writer_closed_.load(std::memory_order_acquire);
  }

  [[nodiscard]] bool reader_is_closed_locked() const {
    return reader_closed_.load(std::memory_order_relaxed);
  }
  [[nodiscard]] bool writer_is_closed_locked() const {
    return writer_closed_.load(std::memory_order_relaxed);
  }

  [[nodiscard]] unsigned int get_reader_flags() const {
    assert(lock_.IsHeld());
    assert(!reader_is_closed_locked());
    unsigned int flags = 0;
    if (writer_is_closed_locked()) flags |= kPollHUp;
    if (!is_empty()) flags |= kPollIn;
    return flags;
  }

  [[nodiscard]] unsigned int get_writer_flags() const {
    assert(lock_.IsHeld());
    assert(!writer_is_closed_locked());
    unsigned int flags = 0;
    if (reader_is_closed_locked()) flags |= kPollErr;
    if (!is_full()) flags |= kPollOut;
    return flags;
  }

  inline void WakeWriters() {
    if constexpr (MultiWriter)
      write_waker_.WakeAll();
    else
      write_waker_.Wake();
  }

  rt::Spin lock_;
  Channel chan_;
  std::atomic<bool> reader_closed_{false};
  std::atomic<bool> writer_closed_{false};

  rt::ThreadWaker read_waker_;
  std::conditional_t<MultiWriter, rt::WaitQueue, rt::ThreadWaker> write_waker_;

  SinglePollSource read_poll_;
  std::conditional_t<MultiWriter, PollSourceSet, SinglePollSource> write_poll_;
};

template <class Channel, bool MultiWriter>
inline void WaitableChannel<Channel, MultiWriter>::CloseWriter(PollSource *p) {
  rt::SpinGuard guard(lock_);
  writer_closed_.store(true, std::memory_order_release);
  if (!reader_is_closed() && read_poll_) {
    read_poll_.Set(kPollHUp);
    read_waker_.Wake();
  }
  if (p) write_poll_.Detach(p);
  WakeWriters();
}

template <class Channel, bool MultiWriter>
inline void WaitableChannel<Channel, MultiWriter>::CloseReader(PollSource *p) {
  rt::SpinGuard guard(lock_);
  reader_closed_.store(true, std::memory_order_release);
  if (!writer_is_closed() && write_poll_) {
    write_poll_.Set(kPollErr);  // POSIX requires this for pipe, not kPollRdHUp
    WakeWriters();
  }
  if (p) read_poll_.Detach(p);
  read_waker_.Wake();
}

}  // namespace

using StreamPipe = WaitableChannel<ByteChannel, false>;
using MsgPipe = WaitableChannel<MessageChannel<void>, false>;
using MultiWriterMsgPipe = WaitableChannel<MessageChannel<void>, true>;

}  // namespace junction