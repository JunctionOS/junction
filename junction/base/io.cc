#include "junction/base/io.h"

#include <algorithm>
#include <cstring>
#include <memory>

namespace junction {

namespace {

constexpr int kStackSlots = 16;

std::span<iovec> PullIOV(std::span<iovec> iov, size_t n) {
  for (auto it = iov.begin(); it < iov.end(); ++it) {
    if (n < it->iov_len) {
      (*it).iov_base = reinterpret_cast<char *>(it->iov_base) + n;
      (*it).iov_len -= n;
      return {it, iov.end()};
    }
    n -= it->iov_len;
  }

  assert(n == 0);
  return {};
}

template <typename T, auto func>
Status<void> DoFull(T &io, std::span<const iovec> iov) {
  // first try to send without copying the vector
  Status<size_t> ret = (io.*func)(iov);
  if (!ret) return MakeError(ret);

  // sum total length and check if everything was transfered
  if (*ret == SumIOV(iov)) return {};

  // partial transfer occurred, copy and update vector, then send the rest
  iovec vstack[kStackSlots];
  std::unique_ptr<iovec[]> vheap;
  iovec *v = vstack;
  if (iov.size() > kStackSlots) {
    vheap = std::make_unique_for_overwrite<iovec[]>(iov.size());
    v = vheap.get();
  }
  std::copy(iov.begin(), iov.end(), v);
  std::span<iovec> s(v, iov.size());
  while (true) {
    s = PullIOV(s, *ret);
    if (s.empty()) break;
    ret = (io.*func)(s);
    if (!ret) return MakeError(ret);
    if constexpr (std::same_as<T, VectoredReader>) {
      if (*ret == 0) return MakeError(EUNEXPECTEDEOF);
    }
  }

  return {};
}

}  // namespace

size_t GenericCopyv(std::span<const iovec> srcv, std::span<iovec> dstv) {
  std::span<std::byte> dst;
  std::span<const std::byte> src;
  size_t read = 0;
  while (true) {
    if (!src.size()) {
      if (!srcv.size()) break;
      src = writable_span(srcv.front());
      srcv = srcv.subspan(1);
    }

    if (!dst.size()) {
      if (!dstv.size()) break;
      dst = readable_span(dstv.front());
      dstv = dstv.subspan(1);
    }

    size_t to_copy = std::min(src.size(), dst.size());
    std::copy_n(src.begin(), to_copy, dst.begin());

    src = src.subspan(to_copy);
    dst = dst.subspan(to_copy);

    read += to_copy;
  }

  return read;
}

Status<void> WritevFull(VectoredWriter &writer, std::span<const iovec> iov) {
  return DoFull<VectoredWriter, &VectoredWriter::Writev>(writer, iov);
}

Status<void> ReadvFull(VectoredReader &reader, std::span<const iovec> iov) {
  return DoFull<VectoredReader, &VectoredReader::Readv>(reader, iov);
}

}  // namespace junction
