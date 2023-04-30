// string.h - utilities for string manipulation

#pragma once

#include <string_view>
#include <vector>

namespace junction {

// ends_with checks if a string ends with another string.
inline bool ends_with(std::string_view value, std::string_view ending) {
  if (ending.size() > value.size()) return false;
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

// starts_with checks if a string starts with another string
inline bool starts_with(std::string_view value, std::string_view starting) {
  if (starting.size() > value.size()) return false;
  return std::equal(starting.begin(), starting.end(), value.begin());
}

// split creates a vector of string views delineated by a seperator character
inline std::vector<std::string_view> split(std::string_view text, char sep) {
  std::vector<std::string_view> tokens;
  std::string_view::size_type start = 0, end = 0;
  while ((end = text.find(sep, start)) != std::string_view::npos) {
    tokens.push_back(text.substr(start, end - start));
    start = end + 1;
  }
  tokens.push_back(text.substr(start));
  return tokens;
}

}  // namespace junction
