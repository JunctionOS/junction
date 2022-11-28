// containers.h - useful container wrappers

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace junction {

// Comparators for unordered_map to be used with std::string_view.
struct string_hash {
  using is_transparent = void;
  [[nodiscard]] size_t operator()(const char *txt) const {
    return std::hash<std::string_view>{}(txt);
  }
  [[nodiscard]] size_t operator()(std::string_view txt) const {
    return std::hash<std::string_view>{}(txt);
  }
  [[nodiscard]] size_t operator()(const std::string &txt) const {
    return std::hash<std::string>{}(txt);
  }
};

// Unordered_map that has a std::string key but can take std::string_view for
// lookups.
template <typename Value>
using string_unordered_map =
    std::unordered_map<std::string, Value, string_hash, std::equal_to<>>;

}  // namespace junction
