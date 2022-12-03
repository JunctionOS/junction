#include "junction/base/arch.h"

#include <cstring>

namespace junction {
namespace {

// The number of retries before giving up. Intel suggests this is a HW error.
constexpr int kRetries = 10;

bool ReadRandomWord(unsigned long long *val) {
  for (int i = 0; i < kRetries; ++i) {
    if (__builtin_ia32_rdrand64_step(val)) return true;
  }
  return false;
}

}  // namespace

Status<size_t> ReadRandom(std::span<std::byte> buf) {
  size_t n = 0;
  while (n < buf.size()) {
    // Copy if less than 8 bytes.
    if (buf.size() - n < sizeof(unsigned long long)) {
      unsigned long long val;
      if (!ReadRandomWord(&val)) return MakeError(EIO);
      std::memcpy(buf.data() + n, &val, buf.size() - n);
      break;
    }

    // Otherwise no need to copy.
    if (!ReadRandomWord(
            reinterpret_cast<unsigned long long *>(buf.data() + n))) {
      return MakeError(EIO);
    }
    n += sizeof(unsigned long long);
  }

  return buf.size();
}

}  // namespace junction
