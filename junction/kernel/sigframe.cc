
#include "junction/kernel/sigframe.h"

#include <cstring>

#include "junction/base/bits.h"

namespace junction {

// Copy a kernel-delivered sigframe to a new stack
k_sigframe *k_sigframe::CopyToStack(uint64_t dest_rsp) const {
  // validate that the kernel used xsave
  BUG_ON(!(uc.uc_flags & kUCFpXstate));

  k_xstate *xstate = reinterpret_cast<k_xstate *>(uc.uc_mcontext.fpstate);
  k_fpx_sw_bytes *fpxs = &xstate->fpstate.sw_reserved;

  // validate magic numbers
  BUG_ON(fpxs->magic1 != kFpXstateMagic1);
  auto *magic2 = reinterpret_cast<unsigned char *>(xstate) + fpxs->xstate_size;
  BUG_ON(*reinterpret_cast<uint32_t *>(magic2) != kFpXstateMagic2);

  // allocate space for xstate
  dest_rsp = AlignDown(dest_rsp - fpxs->extended_size, kXsaveAlignment);
  void *dst_fx_buf = reinterpret_cast<void *>(dest_rsp);
  std::memcpy(dst_fx_buf, xstate, fpxs->extended_size);

  // allocate remainder of sigframe
  dest_rsp -= sizeof(k_sigframe);
  k_sigframe *dst_sigframe = reinterpret_cast<k_sigframe *>(dest_rsp);

  // copy full sigframe
  *dst_sigframe = *this;

  // fix fpstate pointer
  dst_sigframe->uc.uc_mcontext.fpstate =
      reinterpret_cast<_fpstate *>(dst_fx_buf);

  return dst_sigframe;
}
}  // namespace junction