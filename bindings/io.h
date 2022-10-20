// io.h - utilities for I/O

#pragma once

extern "C" {
#include <base/stddef.h>
#include <sys/uio.h>
}

#include <cstddef>
#include <span>

#include "error.h"

namespace rt {

// Reader is a concept for the basic UNIX-style Read method
template <typename T>
concept Reader = requires(T t) {
  {
    t.Read(std::declval<std::span<std::byte>>())
    } -> std::same_as<expected<size_t, Error>>;
};

// Writer is a concept for the basic UNIX-style Write method
template <typename T>
concept Writer = requires(T t) {
  {
    t.Write(std::declval<std::span<const std::byte>>())
    } -> std::same_as<expected<size_t, Error>>;
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

// Reads the full span of bytes.
template <typename T>
expected<void, Error> ReadFull(T *t,
                               std::span<std::byte> buf) requires Reader<T> {
  size_t n = 0;
  while (n < buf.size()) {
    expected<size_t, Error> ret = t->Read({buf.begin() + n, buf.end()});
    if (!ret) return MakeError(ret);
    n += *ret;
  }
  assert(n == buf.size());
  return {};
}

// Writes the full span of bytes.
template <typename T>
expected<void, Error> WriteFull(
    T *t, std::span<const std::byte> buf) requires Writer<T> {
  size_t n = 0;
  while (n < buf.size()) {
    expected<size_t, Error> ret = t->Write({buf.begin() + n, buf.end()});
    if (!ret) return MakeError(ret);
    n += *ret;
  }
  assert(n == buf.size());
  return {};
}

// VectorIO is an interface for vector reads and writes.
class VectorIO {
 public:
  virtual ~VectorIO(){};
  virtual expected<size_t, Error> Readv(std::span<const iovec> sg) = 0;
  virtual expected<size_t, Error> Writev(std::span<const iovec> sg) = 0;
};

expected<void, Error> ReadvFull(VectorIO *io, std::span<const iovec> sg);
expected<void, Error> WritevFull(VectorIO *io, std::span<const iovec> sg);

}  // namespace rt
