#pragma once

#if __has_include(<format>)
#include <format>
#else
// std::format polyfill using fmtlib
#include <fmt/core.h>
namespace std {
using fmt::format;
}
#endif
