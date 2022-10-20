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

#include <string_view>
#include <utility>

#include "expected.h"

namespace rt {

// read() UNIX calls can return this error (not normally an errno)
#define EEOF 0  // end of file

// Asserts if an integer is a valid linux error code
inline void assert_code_is_valid(int code) {
  assert(code >= 0 || code <= EREMOTEIO);
}

class Error {
 public:
  explicit Error(int code) noexcept : code_(code) {
    assert_code_is_valid(code);
  }
  ~Error() {}

  Error(const Error& e) { code_ = e.code_; }
  Error& operator=(const Error& e) {
    code_ = e.code_;
    return *this;
  }
  Error(Error&& e) noexcept : code_(e.code_) {}
  Error& operator=(Error&& e) noexcept {
    std::swap(code_, e.code_);
    return *this;
  }

  // Returns the underlying linux error code.
  int code() const { return code_; }

  // Converts the error to a human readable string.
  std::string_view ToString() const;

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
inline rt::unexpected<Error> MakeError(int code) {
  return rt::unexpected(Error(code));
}

// Returns an unexpected error propogated from another expected type.
//
// The other expected type can have a different value type but must have the
// same error type.
template <typename T>
inline rt::unexpected<Error> MakeError(const rt::expected<T, Error>& ret) {
  assert(!ret);
  return rt::unexpected(ret.error());
}

}  // namespace rt
