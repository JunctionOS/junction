extern "C" {
#include <base/syscall.h>
}

#include <cstring>

#include "junction/base/bits.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/sigframe.h"
#include "junction/syscall/syscall.h"

namespace junction {

void *k_sigframe::CopyXstateToStack(uint64_t *dest_rsp) const {
  // validate that the kernel used xsave
  BUG_ON(!(uc.uc_flags & kUCFpXstate));

  k_xstate *xstate = reinterpret_cast<k_xstate *>(uc.uc_mcontext.fpstate);
  k_fpx_sw_bytes *fpxs = &xstate->fpstate.sw_reserved;

  // validate magic numbers
  BUG_ON(fpxs->magic1 != kFpXstateMagic1);
  auto *magic2 = reinterpret_cast<unsigned char *>(xstate) + fpxs->xstate_size;
  BUG_ON(*reinterpret_cast<uint32_t *>(magic2) != kFpXstateMagic2);

  // allocate space for xstate
  *dest_rsp = AlignDown(*dest_rsp - fpxs->extended_size, kXsaveAlignment);
  void *dst_fx_buf = reinterpret_cast<void *>(*dest_rsp);
  std::memcpy(dst_fx_buf, xstate, fpxs->extended_size);

  return dst_fx_buf;
}

k_sigframe *k_sigframe::CopyToStack(uint64_t *dest_rsp, void *fx_buf) const {
  k_sigframe *dst_sigframe = PushToStack(dest_rsp, *this);

  // fix fpstate pointer
  dst_sigframe->uc.uc_mcontext.fpstate = reinterpret_cast<_fpstate *>(fx_buf);

  return dst_sigframe;
}

extern "C" __nofp void UintrFullRestore(u_sigframe *frame) {
  frame->RestoreXstate();
  nosave_switch(reinterpret_cast<thread_fn_t>(uintr_asm_return),
                reinterpret_cast<uint64_t>(frame), 0);
  std::unreachable();
}

extern "C" void UintrLoopReturn(u_sigframe *frame) {
  Thread &myth = mythread();

  while (true) {
    ClearUIF();
    myth.mark_leave_kernel();
    if (!myth.needs_interrupt()) {
      UintrFullRestore(frame);
      std::unreachable();
    }

    // a signal slipped in, handle it and try again
    myth.mark_enter_kernel();
    SetUIF();

    myth.get_sighand().DeliverSignals(UintrTf(frame), 0);
  }
}

// Restores saved xstates. Must be called from uthread context.
void __nofp u_sigframe::RestoreXstate() const {
  assert(xsave_area);

  thread_t *th = perthread_read(__self);
  assert(th);

  bool is_perthread_area = xsave_area == GetXsaveAreaNoFp(*th->stack);

  // disable interrupts while manipulating th's xsave/xrstor fields
  bool reenable_uif = __builtin_ia32_testui();
  __builtin_ia32_clui();

  XRestore(xsave_area, xsave_features);

  if (is_perthread_area) {
    // mark the per-uthread area as unused
    th->xsave_area_in_use = false;
    // allow potential xsaveopts
    perthread_store(last_xrstor_buf, xsave_area);
  } else {
    // disallow xsaveopt
    perthread_store(last_xrstor_buf, NULL);
  }

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
      *dest_rsp = AlignDown(*dest_rsp - xsave_max_size, kXsaveAlignment);
      new_xarea = reinterpret_cast<unsigned char *>(*dest_rsp);
      std::memcpy(new_xarea, xsave_area, xsave_max_size);
    }
  }

  // allocate remainder of sigframe
  u_sigframe *dst_sigframe = PushToStack(dest_rsp, *this);

  // fix fpstate pointer
  dst_sigframe->xsave_area = new_xarea;

  return dst_sigframe;
}

// Copy a kernel-delivered sigframe to a new stack
k_sigframe *k_sigframe::CopyToStack(uint64_t *dest_rsp) const {
  // Copy xstate
  void *dst_fx_buf = CopyXstateToStack(dest_rsp);
  return CopyToStack(dest_rsp, dst_fx_buf);
}

}  // namespace junction
