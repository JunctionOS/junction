
#include "junction/shim/backend/init.h"

#include <cstring>

#include "junction/kernel/ksys.h"
#include "junction/shim/shim.h"
namespace junction {

Status<void> ShimJmpInit() {
  Status<void> ret =
      KernelMMapFixed(reinterpret_cast<void *>(SHIMCALL_JMPTBL_LOC),
                      sizeof(shim_jmptbl), PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret)) return MakeError(ret);

  std::memcpy(reinterpret_cast<void *>(SHIMCALL_JMPTBL_LOC), shim_jmptbl,
              sizeof(shim_jmptbl));
  return {};
}
}  // namespace junction