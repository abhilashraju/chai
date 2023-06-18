
#pragma once
#include <string_view>
namespace chai {
inline std::string_view operator"" _sv(char const *p, std::size_t n) {
  return std::string_view{p, n};
}
} // namespace bingo
