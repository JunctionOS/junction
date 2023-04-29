// random.cc - support for random number generation
//
// TODO(amb): Add /dev/random and /dev/urandom file support

extern "C" {
#include <sys/random.h>
}

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/kernel/usys.h"

namespace junction {

// if set, use a real random source without PRNG mixing
constexpr unsigned int kRandFlagRandom = GRND_RANDOM;
// if set, returns without blocking when random bytes are not available
constexpr unsigned int kRandFlagNonBlock = GRND_NONBLOCK;

ssize_t usys_getrandom(char *buf, size_t buflen, unsigned int flags) {
  // Use the hardware entropy source (slow)?
  if ((flags & kRandFlagRandom) > 0) {
    bool blocking = !(flags & kRandFlagNonBlock);
    Status<size_t> ret = ReadEntropy(readable_span(buf, buflen), blocking);
    if (!ret) return MakeCError(ret);
    return static_cast<ssize_t>(*ret);
  }

  // Otherwise, entropy + PRNG mixing (fast)
  Status<size_t> ret = ReadRandom(readable_span(buf, buflen));
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

}  // namespace junction
