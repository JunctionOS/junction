
#pragma once

extern "C" {
#include <runtime/thread.h>
#include <signal.h>
}

#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

#include "junction/base/arch.h"
#include "junction/base/bits.h"
#include "junction/bindings/stack.h"
#include "junction/snapshot/cereal.h"

inline constexpr uint64_t kUCFpXstate = 0x1;
inline constexpr uint32_t kFpXstateMagic1 = 0x46505853U;
inline constexpr uint32_t kFpXstateMagic2 = 0x46505845U;

namespace junction {

// Linux metadata embedded in legacy xsave area.
struct k_fpx_sw_bytes {
  /*
   * If set to FP_XSTATE_MAGIC1 then this is an xstate context.
   * 0 if a legacy frame.
   */
  uint32_t magic1;

  /*
   * Total size of the fpstate area:
   *
   *  - if magic1 == 0 then it's sizeof(struct _fpstate)
   *  - if magic1 == FP_XSTATE_MAGIC1 then it's sizeof(struct _xstate)
   *    plus extensions (if any)
   */
  uint32_t extended_size;

  /*
   * Feature bit mask (including FP/SSE/extended state) that is present
   * in the memory layout:
   */
  uint64_t xfeatures;

  /*
   * Actual XSAVE state size, based on the xfeatures saved in the layout.
   * 'extended_size' is greater than 'xstate_size':
   */
  uint32_t xstate_size;

  /* For future use: */
  uint32_t padding[7];
};

struct k_ucontext {
  unsigned long uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  struct sigcontext uc_mcontext;
  unsigned long mask; /* mask last for extensibility */
};

// Constants in syscall.S
static_assert(offsetof(k_ucontext, uc_stack.ss_flags) == 24);
static_assert(offsetof(k_ucontext, mask) == 296);

struct k_sigframe {
  char *pretcode;
  struct k_ucontext uc;
  siginfo_t info;

  static inline k_sigframe *FromUcontext(k_ucontext *uc) {
    return container_of(uc, k_sigframe, uc);
  }

  [[nodiscard]] inline uint64_t GetRsp() const { return uc.uc_mcontext.rsp; }
  [[nodiscard]] inline uint64_t GetRip() const { return uc.uc_mcontext.rip; }

  // Copy this signal frame's xstate to the stack @dest_rsp
  void *CopyXstateToStack(uint64_t *dest_rsp) const;

  // Copy this signal frame to the @dest_rsp, xstate state is at @fx_buf
  k_sigframe *CopyToStack(uint64_t *dest_rsp, void *fx_buf) const;

  // Copy the full signal frame (xstate included) to @dest_rsp
  k_sigframe *CopyToStack(uint64_t *dest_rsp) const;

  void DoSave(cereal::BinaryOutputArchive &ar) const;

  static k_sigframe *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *dest_rsp);
};

static_assert(sizeof(k_sigframe) % 16 == 8);

struct u_sigframe : public thread_tf {
  // Attach dst_buf to this sigframe.
  inline void AttachXstate(void *dst_buf) {
    assert(!xsave_area);
    xsave_area = reinterpret_cast<unsigned char *>(dst_buf);
  }

  // Restore the currently attached extended states. Checks and clears the
  // xsave_area_in_use flag if needed.
  __nofp void RestoreXstate() const;

  // Copy the full signal frame (xstate included) to @dest_rsp
  u_sigframe *CopyToStack(uint64_t *dest_rsp) const;

  [[nodiscard]] inline uint64_t GetRsp() const { return rsp; }
  [[nodiscard]] inline uint64_t GetRip() const { return rip; }

  void DoSave(cereal::BinaryOutputArchive &ar) const;

  static u_sigframe *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *dest_rsp);
};

static_assert(sizeof(u_sigframe) == sizeof(thread_tf));

extern "C" [[noreturn]] __nofp void UintrFullRestore(const u_sigframe *frame);

Status<void> InitXsave();
extern uint64_t xsave_enabled_bitmap;
extern uint32_t xsave_max_sizes[kXsaveMaxComponents];
extern bool xsavec_available;

inline __nofp size_t GetXsaveAreaSize(uint64_t features) {
  // Check that this subsystem has been initialized.
  assert(xsave_enabled_bitmap);
  if (unlikely(!features)) return xsave_max_sizes[0];
  return xsave_max_sizes[63 - __builtin_clzl(features)];
}

inline __nofp size_t GetXsaveAreaSize(xstate *xs) {
  // Check that this is a compacted form xsate.
  if (xs->xstate_hdr.xcomp_bv & BIT(63))
    return GetXsaveAreaSize(xs->xstate_hdr.xcomp_bv & ~BIT(63));
  return GetXsaveAreaSize(xsave_enabled_bitmap);
}

}  // namespace junction
