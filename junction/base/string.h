// string.h - utilities for string manipulation

#pragma once

#include <string_view>
#include <vector>

namespace junction {

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
