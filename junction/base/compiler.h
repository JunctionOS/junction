// compiler.h - compiler tricks

#pragma once

#include <limits>
#include <type_traits>
#include <typeinfo>

namespace junction {

constexpr bool is_debug_build() {
#ifndef NDEBUG
  return true;
#else
  return false;
#endif
}

// Force the compiler to access a memory location.
template <typename T>
T volatile &access_once(T &t)
  requires std::is_integral_v<T>
{
  return static_cast<T volatile &>(t);
}

// Force the compiler to read a memory location.
template <typename T>
T read_once(const T &p)
  requires std::is_integral_v<T>
{
  return static_cast<const T volatile &>(p);
}

// Force the compiler to write a memory location.
template <typename T>
void write_once(T &p, const T &val)
  requires std::is_integral_v<T>
{
  static_cast<T volatile &>(p) = val;
}

// Calculate the maximum number of elements that can be contained in an array.
template <class T>
constexpr size_t ArrayMaxElements() {
  return std::numeric_limits<std::ptrdiff_t>::max() / sizeof(T);
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

namespace detail {
template <typename, template <typename...> typename>
struct is_instantiation_impl : public std::false_type {};

template <template <typename...> typename U, typename... Ts>
struct is_instantiation_impl<U<Ts...>, U> : public std::true_type {};
}  // namespace detail

template <typename T, template <typename...> typename U>
using is_instantiation_of =
    detail::is_instantiation_impl<std::remove_cvref_t<T>, U>;

// is_instantiation_of_v is true if type T is an instantiation of a template U.
template <typename T, template <typename...> typename U>
inline constexpr bool is_instantiation_of_v = is_instantiation_of<T, U>::value;

}  // namespace junction
