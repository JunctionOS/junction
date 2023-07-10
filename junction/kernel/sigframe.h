
#pragma once

extern "C" {
#include <signal.h>
}

#include <cstdint>

inline constexpr uint64_t kUCFpXstate = 0x1;
inline constexpr uint32_t kFpXstateMagic1 = 0x46505853U;
inline constexpr uint32_t kFpXstateMagic2 = 0x46505845U;
inline constexpr size_t kRedzoneSize = 128;
inline constexpr size_t kXsaveAlignment = 64;

namespace junction {

struct k_xstate_header {
  uint64_t xfeatures;
  uint64_t reserved1[2];
  uint64_t reserved2[5];
};

struct k_ymmh_state {
  /* 16x YMM registers, 16 bytes each: */
  uint32_t ymmh_space[64];
};

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

struct k_fpstate_64 {
  uint16_t cwd;
  uint16_t swd;
  /* Note this is not the same as the 32-bit/x87/FSAVE twd: */
  uint16_t twd;
  uint16_t fop;
  uint64_t rip;
  uint64_t rdp;
  uint32_t mxcsr;
  uint32_t mxcsr_mask;
  uint32_t st_space[32];  /*  8x  FP registers, 16 bytes each */
  uint32_t xmm_space[64]; /* 16x XMM registers, 16 bytes each */
  uint32_t reserved2[12];
  union {
    uint32_t reserved3[12];
    struct k_fpx_sw_bytes
        sw_reserved; /* Potential extended state is encoded here */
  };
};

struct k_xstate {
  struct k_fpstate_64 fpstate;
  struct k_xstate_header xstate_hdr;
  struct k_ymmh_state ymmh;
  /* New processor state extensions go here: */
};

struct k_ucontext {
  unsigned long uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  struct sigcontext uc_mcontext;
  unsigned int mask; /* mask last for extensibility */
};

struct k_sigframe {
  char *pretcode;
  struct k_ucontext uc;
  siginfo_t info;

  // The kernel will replace the altstack when we call __rt_sigreturn. Since
  // this call may happen from a different kernel thread then the one that the
  // signal was delivered to, invalidate the altstack recorded in the sigframe.
  inline void InvalidateAltStack() { uc.uc_stack.ss_flags = 4; }

  k_sigframe *CopyToStack(uint64_t dest_rsp) const;
};

inline bool IsOnStack(uint64_t cur_rsp, const stack_t &ss) {
  uint64_t sp = reinterpret_cast<uint64_t>(ss.ss_sp);

  return cur_rsp >= sp && cur_rsp < sp + ss.ss_size;
}

}  // namespace junction