// compiler.h - compiler tricks

#pragma once

#include <typeinfo>

namespace junction {

// Force the compiler to access a memory location.
template <typename T>
T volatile &access_once(T &t) requires std::is_integral_v<T> {
  return static_cast<T volatile &>(t);
}

// Force the compiler to read a memory location.
template <typename T>
T read_once(const T &p) requires std::is_integral_v<T> {
  return static_cast<const T volatile &>(p);
}

// Force the compiler to write a memory location.
template <typename T>
void write_once(T &p, const T &val) requires std::is_integral_v<T> {
  static_cast<T volatile &>(p) = val;
}

template <typename NewT, typename T>
constexpr bool is_most_derived(const T &x) {
  return (typeid(x) == typeid(NewT));
}

// most_derived_cast casts to the most derived type of a base type if possible,
// or returns nullptr if not. It is faster than dynamic_cast and does not use
// RTTI, but only works with the most derived type (i.e., not with intermediate
// types and multiple inheritance).
template <typename NewT, typename T>
NewT *most_derived_cast(T *x) {
  if (is_most_derived<NewT>(*x)) return static_cast<NewT *>(x);
  return nullptr;
}

}  // namespace junction
