// string.h - utilities for string manipulation

#pragma once

#include <string>
#include <string_view>

namespace junction {

// Checks if a string ends with another string.
inline bool ends_with(const std::string_view& value,
                      const std::string_view& ending) {
  if (ending.size() > value.size()) return false;
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

inline bool starts_with(const std::string_view& value,
                        const std::string_view& starting) {
  if (starting.size() > value.size()) return false;
  return std::equal(starting.begin(), starting.end(), value.begin());
}

}  // namespace junction
