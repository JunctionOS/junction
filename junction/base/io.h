// io.h - utilities for I/O

#pragma once

extern "C" {
#include <base/stddef.h>
#include <sys/uio.h>
}

#include <cstddef>
#include <span>

#include "junction/base/error.h"

namespace junction {

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
Status<void> ReadFull(T *t, std::span<std::byte> buf) {
  size_t n = 0;
  while (n < buf.size()) {
    Status<size_t> ret =
        t->Read({buf.begin() + static_cast<ssize_t>(n), buf.end()});
    if (!ret) return MakeError(ret);
    n += *ret;
  }
  assert(n == buf.size());
  return {};
}

// Writes the full span of bytes.
template <Writer T>
Status<void> WriteFull(T *t, std::span<const std::byte> buf) {
  size_t n = 0;
  while (n < buf.size()) {
    Status<size_t> ret =
        t->Write({buf.begin() + static_cast<ssize_t>(n), buf.end()});
    if (!ret) return MakeError(ret);
    n += *ret;
  }
  assert(n == buf.size());
  return {};
}

// VectorIO is an interface for vector reads and writes.
class VectorIO {
 public:
  virtual ~VectorIO() = default;
  virtual Status<size_t> Readv(std::span<const iovec> iov) = 0;
  virtual Status<size_t> Writev(std::span<const iovec> iov) = 0;
};

Status<void> ReadvFull(VectorIO *io, std::span<const iovec> iov);
Status<void> WritevFull(VectorIO *io, std::span<const iovec> iov);

}  // namespace junction
