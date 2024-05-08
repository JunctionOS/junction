// string.h - utilities for string manipulation

#pragma once

#include <algorithm>
#include <limits>
#include <string_view>
#include <vector>

namespace junction {

// split creates a vector of string views delineated by a seperator character
inline std::vector<std::string_view> split(
    std::string_view text, char sep, std::optional<size_t> max = std::nullopt) {
  std::vector<std::string_view> tokens;
  std::string_view::size_type start = 0, end;

  while ((end = text.find(sep, start)) != std::string_view::npos) {
    tokens.push_back(text.substr(start, end - start));
    start = end + 1;
    if (max && tokens.size() >= *max) break;
  }
  tokens.push_back(text.substr(start));
  return tokens;
}

inline std::vector<std::string_view> rsplit(
    std::string_view text, char sep, std::optional<size_t> max = std::nullopt) {
  std::vector<std::string_view> tokens;
  std::string_view::size_type start, end = text.size() - 1;

  while ((start = text.rfind(sep, end)) != std::string_view::npos) {
    tokens.push_back(text.substr(start + 1, end - start));
    end = start - 1;
    if (max && tokens.size() >= *max) break;
    if (start == 0) break;
  }
  if (end + 1 > 0) tokens.push_back(text.substr(0, end + 1));
  std::reverse(tokens.begin(), tokens.end());
  return tokens;
}

}  // namespace junction
