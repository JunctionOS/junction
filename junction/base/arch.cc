// arch.cc - support for x86_64 CPU features
//
// TODO(amb): Do misaligned reads still work with RDRAND/RDSEED?

#include "junction/base/arch.h"

#include <cstring>

namespace junction {
namespace {

bool ReadRandomWord(uint64_t *val) {
  // The number of retries before giving up. Intel suggests this is a HW error.
  static constexpr int kRetries = 10;
  bool ok;

  for (int i = 0; i < kRetries; ++i) {
    asm volatile("rdrand %0" : "=r"(*val), "=@ccc"(ok));
    if (ok) return true;
  }
  return false;
}

bool ReadSeedWord(uint64_t *val, bool blocking) {
  bool ok;

  while (true) {
    asm volatile("rdseed %0" : "=r"(*val), "=@ccc"(ok));
    if (!blocking || ok) break;
    CPURelax();
  }

  return ok;
}

}  // namespace

Status<size_t> ReadRandom(std::span<std::byte> buf) {
  size_t n = 0;
  while (n < buf.size()) {
    // Copy if less than 8 bytes.
    if (buf.size() - n < sizeof(uint64_t)) {
      uint64_t val;
      if (!ReadRandomWord(&val)) return MakeError(EIO);
      std::memcpy(buf.data() + n, &val, buf.size() - n);
      break;
    }

    // Otherwise no need to copy.
    if (!ReadRandomWord(reinterpret_cast<uint64_t *>(buf.data() + n)))
      return MakeError(EIO);
    n += sizeof(uint64_t);
  }

  return buf.size();
}

Status<size_t> ReadEntropy(std::span<std::byte> buf, bool blocking) {
  size_t n = 0;
  while (n < buf.size()) {
    // Copy if less than 8 bytes.
    if (buf.size() - n < sizeof(uint64_t)) {
      uint64_t val;
      if (!ReadSeedWord(&val, blocking)) break;
      std::memcpy(buf.data() + n, &val, buf.size() - n);
      break;
    }

    // Otherwise no need to copy.
    if (!ReadSeedWord(reinterpret_cast<uint64_t *>(buf.data() + n), blocking))
      break;
    n += sizeof(uint64_t);
  }

  if (!buf.empty() && n == 0) return MakeError(EAGAIN);
  return buf.size();
}

}  // namespace junction
