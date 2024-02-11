// io.h - utilities for I/O
//
// TODO(amb): we should remove WriteFull(), but first Caladan's TCP stack must
// be fixed to never return less than the requested bytes. This is the correct
// POSIX behavior for write(), but ReadFull() is still needed for read().

#pragma once

extern "C" {
#include <base/stddef.h>
#include <sys/uio.h>
}

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <streambuf>
#include <type_traits>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/compiler.h"
#include "junction/base/error.h"

namespace junction {

inline constexpr size_t kDefaultBufferSize = kPageSize * 16;

// Reader is a concept for the basic UNIX-style Read method
template <typename T>
concept Reader = requires(T t) {
  {
    t.Read(std::declval<std::span<std::byte>>())
  } -> std::same_as<Status<size_t>>;
};

// Writer is a concept for the basic UNIX-style Write method
template <typename T>
concept Writer = requires(T t) {
  {
    t.Write(std::declval<std::span<const std::byte>>())
  } -> std::same_as<Status<size_t>>;
};

// Cast an object as a const byte span (for use with Write())
template <typename T>
std::span<const std::byte, sizeof(T)> byte_view(const T &t) {
  return std::as_bytes(std::span<const T, 1>{std::addressof(t), 1});
}

// Cast an object as a mutable byte span (for use with Read())
template <typename T>
std::span<std::byte, sizeof(T)> writable_byte_view(T &t) {
  return std::as_writable_bytes(std::span<T, 1>{std::addressof(t), 1});
}

// Cast a legacy UNIX read buffer as a span.
inline std::span<std::byte> readable_span(char *buf, size_t len) {
  return {reinterpret_cast<std::byte *>(buf), len};
}

// Cast a legacy UNIX write buffer as a span.
inline std::span<const std::byte> writable_span(const char *buf, size_t len) {
  return {reinterpret_cast<const std::byte *>(buf), len};
}

// Reads the full span of bytes.
template <Reader T>
Status<void> ReadFull(T &t, std::span<std::byte> buf) {
  size_t n = 0;
  while (n < buf.size()) {
    Status<size_t> ret = t.Read(buf.subspan(n));
    if (!ret) return MakeError(ret);
    if (*ret == 0) return MakeError(EIO);
    n += *ret;
  }
  assert(n == buf.size());
  return {};
}

// Writes the full span of bytes.
template <Writer T>
Status<void> WriteFull(T &t, std::span<const std::byte> buf) {
  size_t n = 0;
  while (n < buf.size()) {
    Status<size_t> ret = t.Write(buf.subspan(n));
    if (!ret) return MakeError(ret);
    n += *ret;
  }
  assert(n == buf.size());
  return {};
}

template <Writer T>
class BufferedWriter {
 public:
  BufferedWriter(T &out, size_t len = kDefaultBufferSize) noexcept : out_(out) {
    buf_.reserve(len);
  }

  // disable copy
  BufferedWriter(const BufferedWriter &w) = delete;
  BufferedWriter &operator=(const BufferedWriter &w) = delete;

  // allow move
  BufferedWriter(BufferedWriter &&w) noexcept
      : out_(w.out_), buf_(std::move(w.buf_)) {}
  BufferedWriter &operator=(BufferedWriter &&w) noexcept {
    out_ = w.out_;
    buf_ = std::move(w.buf_);
    return *this;
  }

  ~BufferedWriter() { Flush(); }

  Status<size_t> Write(std::span<const std::byte> src) {
    size_t in_size = src.size();
    size_t n = 0;
    while (n < in_size) {
      // fast path: avoid extra copies if @src is already large enough
      if (buf_.empty() && (in_size - n) >= buf_.capacity()) {
        Status<void> ret = WriteFull(out_, src.subspan(n));
        if (unlikely(!ret)) return MakeError(ret);
        break;
      }

      // cold path: copy @src into the buffer
      size_t copy_size = std::min(in_size - n, buf_.capacity() - buf_.size());
      std::ranges::copy(src.begin() + static_cast<ssize_t>(n),
                        src.begin() + static_cast<ssize_t>(n + copy_size),
                        std::back_inserter(buf_));
      n += copy_size;

      if (buf_.size() == buf_.capacity()) {
        Status<void> ret = Flush();
        if (unlikely(!ret)) return MakeError(ret);
      }
    }
    return in_size;
  }

  Status<void> Flush() {
    Status<void> ret = WriteFull(out_, buf_);
    buf_.clear();
    if (!ret) return MakeError(ret);
    return {};
  }

 private:
  T &out_;
  std::vector<std::byte> buf_;
};

template <Reader T>
class BufferedReader {
 public:
  BufferedReader(T &in, size_t len = kDefaultBufferSize) noexcept
      : in_(in), len_(len) {
    buf_ = std::make_unique_for_overwrite<std::byte[]>(len);
  }

  // disable copy
  BufferedReader(const BufferedReader &r) = delete;
  BufferedReader &operator=(const BufferedReader &r) = delete;

  // allow move
  BufferedReader(BufferedReader &&r) noexcept
      : in_(r.in_), len_(r.len_), buf_(std::move(r.buf_)) {}
  BufferedReader &operator=(BufferedReader &&r) noexcept {
    in_ = r.in_;
    len_ = r.len_;
    buf_ = std::move(r.buf_);
    return *this;
  }

  ~BufferedReader() = default;

  Status<size_t> Read(std::span<std::byte> dst) {
    // Try to read from the buffer first
    size_t n = ReadFromBuffer(dst);
    if (n == dst.size()) return n;

    // Read directly from the reader without copying if dst is large enough
    dst = dst.subspan(n);
    if (dst.size() >= len_) {
      Status<size_t> ret = in_.Read({buf_.get(), len_});
      if (!ret) return MakeError(ret);
      return n + *ret;
    }

    // Otherwise, refill the buffer and copy what's still needed
    assert(pos_.empty());
    Status<void> ret = Refill();
    if (!ret) return MakeError(ret);
    return n + ReadFromBuffer(dst);
  }

 private:
  size_t ReadFromBuffer(std::span<std::byte> dst) {
    size_t n = std::min(dst.size(), pos_.size());
    if (n == 0) return 0;
    std::copy_n(dst.begin(), n, pos_.begin());
    pos_ = pos_.subspan(n);
    return n;
  }

  Status<void> Refill() {
    Status<size_t> ret = in_.Read({buf_.get(), len_});
    if (!ret) return MakeError(ret);
    pos_ = std::span(buf_.get(), *ret);
    return {};
  }

  T &in_;
  size_t len_;
  std::unique_ptr<std::byte[]> buf_;
  std::span<const std::byte> pos_;
};

// StreamBufferReader provides interoperability with std::streambuf for reads
template <Reader T>
class StreamBufferReader : public std::streambuf {
 public:
  StreamBufferReader(T &in, size_t len = kDefaultBufferSize) noexcept
      : in_(in),
        buf_(std::make_unique_for_overwrite<std::byte[]>(len)),
        len_(len) {
    char *ptr = reinterpret_cast<char *>(buf_.get());
    setg(ptr, ptr, ptr);
  }
  // disable copy.
  StreamBufferReader(const StreamBufferReader &r) = delete;
  StreamBufferReader &operator=(const StreamBufferReader &r) = delete;

  // allow move.
  StreamBufferReader(StreamBufferReader &&r) noexcept
      : in_(r.in_), buf_(std::move(r.buf_)), len_(r.len_) {
    setg(r.start(), r.pos(), r.end());
    r.setg(nullptr, nullptr, nullptr);
  }
  StreamBufferReader &operator=(StreamBufferReader &&r) noexcept {
    in_ = r.in_;
    buf_ = std::move(r.buf_);
    len_ = r.len_;
    setg(r.start(), r.pos(), r.end());
    r.setg(nullptr, nullptr, nullptr);
    return *this;
  }
  ~StreamBufferReader() = default;

 protected:
  // xsgetn has ReadFull semantics
  //
  // From the docs:
  // "Retrieves characters from the controlled input sequence and stores them in
  // the array pointed by s, until either n characters have been extracted or
  // the end of the sequence is reached."
  //
  // This implementation translates all errors to EOF and returns the number of
  // bytes copied to dst before hitting EOF
  std::streamsize xsgetn(char *s, std::streamsize out_size) override {
    std::span<std::byte> dst = readable_span(s, out_size);
    std::streamsize n = 0;

    while (n < out_size) {
      if (bytes_left() == 0) {
        // fast path: copy to dst span if remaining size is >= the internal
        // buffer's size
        while (out_size - n >= len_) {
          // read directly to the dst span.
          Status<size_t> ret = in_.Read(dst.subspan(n));
          if (!ret) return n;
          n += *ret;
          if (n == out_size) return n;
        }

        if (Fill(out_size - n) == 0) return n;
      }

      // copy from internal buf to
      size_t copy_size = std::min(out_size - n, bytes_left());
      std::memcpy(s + n, pos(), copy_size);
      inc_pos(copy_size);
      n += copy_size;
    }

    return out_size;
  }

  int_type underflow() override {
    if (bytes_left() == 0 && Fill(1) == 0) return std::char_traits<char>::eof();

    // return character at pos
    return std::char_traits<char>::not_eof(*pos());
  }

 private:
  // helpers
  [[nodiscard]] inline char *start() const { return eback(); }
  [[nodiscard]] inline char *pos() const { return gptr(); }
  [[nodiscard]] inline char *end() const { return egptr(); }
  inline void set_avail_bytes(size_t total) {
    assert(total <= len_);
    setg(start(), start(), start() + total);
  }
  inline void inc_pos(size_t n) {
    assert(pos() + n <= end());
    gbump(static_cast<int>(n));
  }
  [[nodiscard]] inline size_t bytes_left() const { return end() - pos(); }

  // Fill overwrites the contents of buf_ reading as much as possible
  // from the underlying Reader until at least min_size bytes are read.
  //
  // Returns the number of bytes read, ignoring errors returned from Read.
  size_t Fill(size_t min_size) {
    assert(!bytes_left());
    size_t n = 0;
    while (n < min_size) {
      Status<size_t> ret = in_.Read(readable_span(start() + n, len_ - n));
      if (!ret || *ret == 0) break;
      n += *ret;
    }
    set_avail_bytes(n);
    return n;
  }

  T &in_;
  size_t len_;
  std::unique_ptr<std::byte[]> buf_;
};

// StreamBufferWriter provides interoperability with std::streambuf for writes
template <Writer T>
class StreamBufferWriter final : public std::streambuf {
 public:
  StreamBufferWriter(T &t, size_t len = kDefaultBufferSize)
      : out_(t),
        len_(len),
        buf_(std::make_unique_for_overwrite<std::byte[]>(len)) {
    char *ptr = reinterpret_cast<char *>(buf_.get());
    setp(ptr, ptr + len);
  }
  // disable copy.
  StreamBufferWriter(const StreamBufferWriter &w) = delete;
  StreamBufferWriter &operator=(const StreamBufferWriter &w) = delete;

  // allow move.
  StreamBufferWriter(StreamBufferWriter &&w) noexcept
      : out_(w.out_), buf_(std::move(w.buf_)), len_(w.len_) {
    setp(w.start(), w.end());
    w.setp(nullptr, nullptr);
  }
  StreamBufferWriter &operator=(StreamBufferWriter &&w) noexcept {
    out_ = w.out_;
    buf_ = std::move(w.buf_);
    len_ = w.len_;
    setp(w.start(), w.end());
    w.setp(nullptr, nullptr);
    return *this;
  }
  ~StreamBufferWriter() = default;

 protected:
  std::streamsize xsputn(const char *s, std::streamsize n) override {
    std::span<const std::byte> src = writable_span(s, n);

    // Flush pending buffer first
    if (pos() > start()) {
      size_t n_copied = WriteToBuffer(src);
      if (sync() == -1) return 0;
      src = src.subspan(n_copied);
      if (src.empty()) return n_copied;
    }

    // Write without buffering if remaining payload is large enough
    if (src.size() >= len_) {
      Status<void> ret = WriteFull(out_, src);
      if (!ret) return 0;
      return n;
    }

    // Otherwise write the rest to the buffer
    assert(src.size() == bytes_left());
    size_t n_copied = WriteToBuffer(src);
    assert(n_copied < len_);
    return n;
  }

  int_type overflow(int_type ch) override {
    if (sync() == -1) return traits_type::eof();
    *pptr() = std::char_traits<char>::to_char_type(ch);
    inc_pos(1);
    return traits_type::not_eof(ch);
  }

  int sync() override {
    Status<void> ret = WriteFull(out_, {start(), len_});
    if (!ret) return -1;
    setp(start(), start() + len_);
    return 0;
  }

 private:
  // helpers
  [[nodiscard]] inline char *start() const { return pbase(); }
  [[nodiscard]] inline char *pos() const { return pptr(); }
  [[nodiscard]] inline char *end() const { return epptr(); }
  inline void inc_pos(size_t n) {
    assert(pos() + n <= end());
    pbump(static_cast<int>(n));
  }
  [[nodiscard]] inline size_t bytes_left() const { return end() - pos(); }

  size_t WriteToBuffer(std::span<const std::byte> src) {
    assert(bytes_left() > 0);
    size_t n = std::min(src.size(), bytes_left());
    if (n > 0) std::memcpy(start(), src.data(), n);
    inc_pos(n);
    return n;
  }

  T &out_;
  size_t len_;
  std::unique_ptr<std::byte[]> buf_;
};

// VectoredReader is an interface for vector reads.
class VectoredReader {
 public:
  virtual ~VectoredReader() = default;
  virtual Status<size_t> Readv(std::span<const iovec> iov) = 0;
};

Status<void> ReadvFull(VectoredReader &reader, std::span<const iovec> iov);

// VectoredWriter is an interface for vector writes.
class VectoredWriter {
 public:
  virtual ~VectoredWriter() = default;
  virtual Status<size_t> Writev(std::span<const iovec> iov) = 0;
};

Status<void> WritevFull(VectoredWriter &writer, std::span<const iovec> iov);

}  // namespace junction
