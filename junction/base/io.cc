#include "junction/base/io.h"

#include <algorithm>
#include <cstring>
#include <memory>

namespace {

constexpr int kStackSlots = 8;

size_t SumIOV(std::span<const iovec> iov) {
  size_t len = 0;
  for (const iovec& e : iov) {
    len += e.iov_len;
  }
  return len;
}

std::span<iovec> PullIOV(std::span<iovec> iov, size_t n) {
  for (auto it = iov.begin(); it < iov.end(); ++it) {
    if (n < it->iov_len) {
      (*it).iov_base = reinterpret_cast<char*>(it->iov_base) + n;
      (*it).iov_len -= n;
      return {it, iov.end()};
    }
    n -= it->iov_len;
  }

  assert(n == 0);
  return {};
}

}  // namespace
