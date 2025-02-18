extern "C" {
#include <base/syscall.h>
}

#include <cstring>

#include "junction/base/arch.h"
#include "junction/base/bits.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/sigframe.h"
#include "junction/syscall/syscall.h"

namespace junction {

// Bitmap of components that we can support.
uint64_t xsave_enabled_bitmap;

// Entry @i contains the size needed for a compact xsave area when @i is the msb
// in the saved set of features.
uint32_t xsave_max_sizes[kXsaveMaxComponents];

void *k_sigframe::CopyXstateToStack(uint64_t *dest_rsp) const {
  // validate that the kernel used xsave
  BUG_ON(!(uc.uc_flags & kUCFpXstate));

  xstate *xs = reinterpret_cast<xstate *>(uc.uc_mcontext.fpstate);
  k_fpx_sw_bytes *fpxs =
      reinterpret_cast<k_fpx_sw_bytes *>(xs->fpstate.sw_reserved);

  // validate magic numbers
  BUG_ON(fpxs->magic1 != kFpXstateMagic1);
  auto *magic2 = reinterpret_cast<unsigned char *>(xs) + fpxs->xstate_size;
  BUG_ON(*reinterpret_cast<uint32_t *>(magic2) != kFpXstateMagic2);

  // allocate space for xstate
  *dest_rsp = AlignDown(*dest_rsp - fpxs->extended_size, kXsaveAlignment);
  void *dst_fx_buf = reinterpret_cast<void *>(*dest_rsp);
  std::memcpy(dst_fx_buf, xs, fpxs->extended_size);

  return dst_fx_buf;
}

k_sigframe *k_sigframe::CopyToStack(uint64_t *dest_rsp, void *fx_buf) const {
  k_sigframe *dst_sigframe = PushToStack(dest_rsp, *this);

  // fix fpstate pointer
  dst_sigframe->uc.uc_mcontext.fpstate = reinterpret_cast<_fpstate *>(fx_buf);

  return dst_sigframe;
}

void k_sigframe::DoSave(cereal::BinaryOutputArchive &archive) const {
  xstate *xs = reinterpret_cast<xstate *>(uc.uc_mcontext.fpstate);
  k_fpx_sw_bytes *fpxs =
      reinterpret_cast<k_fpx_sw_bytes *>(xs->fpstate.sw_reserved);

  // validate magic numbers
  BUG_ON(fpxs->magic1 != kFpXstateMagic1);
  auto *magic2 = reinterpret_cast<unsigned char *>(xs) + fpxs->xstate_size;
  BUG_ON(*reinterpret_cast<uint32_t *>(magic2) != kFpXstateMagic2);

  archive(fpxs->extended_size);
  archive(cereal::binary_data(xs, fpxs->extended_size));
  archive(cereal::binary_data(this, sizeof(k_sigframe)));
}

k_sigframe *k_sigframe::DoLoad(cereal::BinaryInputArchive &archive,
                               uint64_t *dest_rsp) {
  uint32_t extended_size;
  archive(extended_size);
  *dest_rsp = AlignDown(*dest_rsp - extended_size, kXsaveAlignment);
  void *dst_fx_buf = reinterpret_cast<void *>(*dest_rsp);
  archive(cereal::binary_data(dst_fx_buf, extended_size));

  k_sigframe *frame = AllocateOnStack<k_sigframe>(dest_rsp);
  archive(cereal::binary_data(frame, sizeof(k_sigframe)));

  frame->uc.uc_mcontext.fpstate = reinterpret_cast<_fpstate *>(dst_fx_buf);
  return frame;
}

// Immediately restore a UIPI sigframe.
extern "C" [[noreturn]] __nofp void UintrFullRestore(const u_sigframe *frame) {
  assert_stack_is_aligned();
  frame->RestoreXstate();
  nosave_switch(reinterpret_cast<thread_fn_t>(uintr_asm_return),
                reinterpret_cast<uint64_t>(frame), 0);
  std::unreachable();
}

// Restores saved xstates. Must be called from uthread context.
void __nofp u_sigframe::RestoreXstate() const {
  assert(xsave_area);

  thread_t *th = perthread_read(__self);
  assert(th);

  bool is_perthread_area = xsave_area == GetXsaveArea(*th->stack);

  // disable interrupts while manipulating th's xsave/xrstor fields
  bool reenable_uif = __builtin_ia32_testui();
  __builtin_ia32_clui();

  XRestore(xsave_area);

  // mark the per-uthread area as unused
  if (is_perthread_area) th->xsave_area_in_use = false;

  if (reenable_uif) __builtin_ia32_stui();
}

u_sigframe *u_sigframe::CopyToStack(uint64_t *dest_rsp) const {
  unsigned char *new_xarea = nullptr;

  if (xsave_area) {
    thread_t *th = thread_self();
    // don't make copies of the per-uthread xsave area.
    if (xsave_area == GetXsaveArea(*th->stack)) {
      assert(!!th->xsave_area_in_use);
      new_xarea = xsave_area;
    } else {
      size_t len = GetXSaveSize(xsave_area);
      *dest_rsp = AlignDown(*dest_rsp - len, kXsaveAlignment);
      new_xarea = reinterpret_cast<unsigned char *>(*dest_rsp);
      std::memcpy(new_xarea, xsave_area, len);
    }
  }

  // allocate remainder of sigframe
  u_sigframe *dst_sigframe = PushToStack(dest_rsp, *this);

  // fix fpstate pointer
  dst_sigframe->xsave_area = new_xarea;

  return dst_sigframe;
}

void u_sigframe::DoSave(cereal::BinaryOutputArchive &archive) const {
  assert(xsave_area);
  size_t len = GetXSaveSize(xsave_area);
  assert(len);
  archive(len);
  archive(cereal::binary_data(xsave_area, len));
  archive(cereal::binary_data(this, sizeof(u_sigframe)));
}

u_sigframe *u_sigframe::DoLoad(cereal::BinaryInputArchive &archive,
                               uint64_t *dest_rsp) {
  uint64_t len;
  archive(len);

  *dest_rsp = AlignDown(*dest_rsp - len, kXsaveAlignment);
  unsigned char *new_xarea = reinterpret_cast<unsigned char *>(*dest_rsp);
  archive(cereal::binary_data(new_xarea, len));

  u_sigframe *dst_sigframe = AllocateOnStack<u_sigframe>(dest_rsp);
  archive(cereal::binary_data(dst_sigframe, sizeof(u_sigframe)));
  dst_sigframe->xsave_area = new_xarea;

  return dst_sigframe;
}

// Copy a kernel-delivered sigframe to a new stack
k_sigframe *k_sigframe::CopyToStack(uint64_t *dest_rsp) const {
  // Copy xstate
  void *dst_fx_buf = CopyXstateToStack(dest_rsp);
  return CopyToStack(dest_rsp, dst_fx_buf);
}

// Compute a table of xsave buffer sizes depending on the highest order bit that
// is set. It is too expensive to determine the minimal buffer size at
// XSaveCompact time because the set of components that are active can be
// different each time. Instead we approximate this size by assuming that if
// feature i is in use, then every feature j < i is also in use (excluding those
// that are not enabled).
Status<void> InitXsave() {
  if (!uintr_enabled) return {};

  // Fill the xstate component table
  cpuid_info regs;
  cpuid(kXsaveCpuid, 0, &regs);
  size_t enabled_bitmap = regs.eax;
  enabled_bitmap |= (uint64_t)regs.edx << 32;

  size_t last_size = offsetof(xstate, xsave_area);

  // Legacy state area is always included.
  xsave_max_sizes[0] = xsave_max_sizes[1] = last_size;

  for (size_t i = 2; i < kXsaveMaxComponents; i++) {
    if ((enabled_bitmap & BIT(i)) == 0) continue;
    cpuid(kXsaveCpuid, i, &regs);

    bool align = (regs.ecx & BIT(1)) != 0;
    if (align) last_size = AlignUp(last_size, 64);
    last_size += regs.eax;
    xsave_max_sizes[i] = last_size;
  }

  // Validate our choice for fixed XSAVE_AREA_SIZE
  if (last_size > XSAVE_AREA_SIZE) {
    LOG(ERR) << "ERROR: this machine requires " << last_size
             << " bytes for XSAVE area, but only " << XSAVE_AREA_SIZE
             << " bytes were reserved. "
             << "Please recompile with a larger XSAVE_AREA_RESERVED.";
    return MakeError(EINVAL);
  }

  store_release(&xsave_enabled_bitmap, enabled_bitmap);

  return {};
}

}  // namespace junction
