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

namespace junction {

Status<void> WritevFull(VectorIO* io, std::span<const iovec> iov) {
  // first try to send without copying the vector
  Status<size_t> ret = io->Writev(iov);
  if (!ret) return MakeError(ret);

  // sum total length and check if everything was transfered
  if (*ret == SumIOV(iov)) return {};

  // partial transfer occurred, copy and update vector, then send the rest
  iovec vstack[kStackSlots];
  std::unique_ptr<iovec[]> vheap;
  iovec* v = vstack;
  if (iov.size() > kStackSlots) {
    vheap = std::unique_ptr<iovec[]>{new iovec[iov.size()]};
    v = vheap.get();
  }
  std::copy(iov.begin(), iov.end(), v);
  std::span<iovec> s(v, iov.size());
  while (true) {
    s = PullIOV(s, *ret);
    if (s.empty()) break;
    ret = io->Writev(s);
    if (!ret) return MakeError(ret);
  }

  return {};
}

Status<void> ReadvFull(VectorIO* io, std::span<const iovec> iov) {
  // first try to send without copying the vector
  Status<size_t> ret = io->Readv(iov);
  if (!ret) return MakeError(ret);

  // sum total length and check if everything was transfered
  if (*ret == SumIOV(iov)) return {};

  // partial transfer occurred, copy and update vector, then receive the rest
  iovec vstack[kStackSlots];
  std::unique_ptr<iovec[]> vheap;
  iovec* v = vstack;
  if (iov.size() > kStackSlots) {
    vheap = std::unique_ptr<iovec[]>{new iovec[iov.size()]};
    v = vheap.get();
  }
  std::copy(iov.begin(), iov.end(), v);
  std::span<iovec> s(v, iov.size());
  while (true) {
    s = PullIOV(s, *ret);
    if (s.empty()) break;
    ret = io->Readv(s);
    if (!ret) return MakeError(ret);
  }

  return {};
}

}  // namespace junction
