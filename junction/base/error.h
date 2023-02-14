// error.h - error handling
//
// We have our own error class because Linux has its own error numbers,
// including some that are not included in the POSIX standard. Unfortunately,
// std::errc only has the POSIX error codes.
//
// Our strategy is to use Linux error codes throughout the project so that
// we can simply pass them to usercode without any extra translation.

#pragma once

extern "C" {
#include "base/stddef.h"
}

#include <expected>
#include <string_view>
#include <utility>

namespace junction {

// read() UNIX calls can return this error (not normally an errno)
#define EEOF 0  // end of file

// Asserts if an integer is a valid linux error code
inline void assert_code_is_valid(int code) {
  assert(code >= 0 && code <= EREMOTEIO);
}

class Error {
 public:
  explicit Error(int code) noexcept : code_(code) {
    assert_code_is_valid(code);
  }
  ~Error() = default;

  Error(const Error& e) { code_ = e.code_; }
  Error& operator=(const Error& e) = default;
  Error(Error&& e) noexcept : code_(e.code_) {}
  Error& operator=(Error&& e) noexcept {
    std::swap(code_, e.code_);
    return *this;
  }

  // Returns the underlying linux error code.
  [[nodiscard]] int code() const { return code_; }

  // Converts the error to a human readable string.
  [[nodiscard]] std::string_view ToString() const;

 private:
  int code_;
};

// Operator overloads for error comparisons.
inline bool operator==(const Error& lhs, const Error& rhs) {
  return lhs.code() == rhs.code();
}
inline bool operator!=(const Error& lhs, const Error& rhs) {
  return lhs.code() != rhs.code();
}
inline bool operator==(const Error& lhs, int rhs) { return lhs.code() == rhs; }
inline bool operator==(int lhs, const Error& rhs) { return lhs == rhs.code(); }
inline bool operator!=(const Error& lhs, int rhs) { return lhs.code() != rhs; }
inline bool operator!=(int lhs, const Error& rhs) { return lhs != rhs.code(); }

// Prints a human readable explanation of the error to an output stream.
std::ostream& operator<<(std::ostream& os, const Error& x);

// Returns an unexpected error object from an errno code.
[[nodiscard]] inline std::unexpected<Error> MakeError(int code) {
  return std::unexpected(Error(code));
}

// Returns an unexpected error propogated from another expected type.
//
// The other expected type can have a different value type but must have the
// same error type.
template <typename T>
[[nodiscard]] inline std::unexpected<Error> MakeError(
    const std::expected<T, Error>& ret) {
  assert(!ret);
  return std::unexpected(ret.error());
}

// Returns a C errno code as a negative int.
template <typename T>
[[nodiscard]] inline int MakeCError(const std::expected<T, Error>& ret) {
  assert(!ret);
  return -ret.error().code();
}

// A shorthand for making an expected with a value type 'T' and an error type
// 'Error'. This is convenient because 'Error' is the default error type
// throughout this project.
//
// Note that a function should never return an 'Error' directly, even if its
// value type is 'void'. Instead use the Status API below.
//
// Example:
//  Status<size_t> ret = Read(buf);
//  if (!ret) return MakeError(ret);
//  // success, inspect *ret to get the length
template <typename T>
using Status = std::expected<T, Error>;

}  // namespace junction
