// random.cc - support for random number generation
//
// TODO(amb): Add /dev/random and /dev/urandom file support
// TODO(amb): Support RDSEED too?

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/kernel/usys.h"

namespace junction {

ssize_t usys_getrandom(char *buf, size_t buflen, unsigned int flags) {
  Status<size_t> ret = ReadRandom(readable_span(buf, buflen));
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

}  // namespace junction
