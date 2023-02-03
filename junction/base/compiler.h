// compiler.h - compiler tricks

#pragma once

#include <typeinfo>

namespace junction {

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
