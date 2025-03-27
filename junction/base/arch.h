// arch.h - x86 constants and utilities

#pragma once

extern "C" {
#include <asm/ops.h>
}

#include <immintrin.h>

#include <span>

#include "junction/base/bits.h"
#include "junction/base/error.h"

namespace junction {

inline constexpr size_t kPageSize = 4096;
inline constexpr size_t kLargePageSize = 2097152;
inline constexpr size_t kCacheLineSize = 64;
inline constexpr size_t kXsaveAlignment = 64;
inline constexpr size_t kXsaveMaxComponents = 19;
inline constexpr uint32_t kXsaveCpuid = 13;

// PageAlign aligns an address upward to the nearest page size
template <typename T>
constexpr T PageAlign(T addr)
  requires std::is_unsigned_v<T>
{
  return AlignUp(addr, kPageSize);
}

template <typename P>
constexpr std::byte *PageAlign(P ptr)
  requires std::is_pointer_v<P>
{
  uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
  return reinterpret_cast<std::byte *>(PageAlign(addr));
}

// PageAlignDown aligns an address downward to the nearest page size
template <typename T>
constexpr T PageAlignDown(T addr)
  requires std::is_unsigned_v<T>
{
  return AlignDown(addr, kPageSize);
}

template <typename P>
constexpr std::byte *PageAlignDown(P ptr)
  requires std::is_pointer_v<P>
{
  uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
  return reinterpret_cast<std::byte *>(PageAlignDown(addr));
}

// IsPageAligned returns true if aligned to a page
template <typename T>
constexpr bool IsPageAligned(T addr)
  requires std::is_unsigned_v<T>
{
  return PageAlign(addr) == addr;
}

// SetFSBase sets the %FS.base value.
inline void SetFSBase(uint64_t val) { _writefsbase_u64(val); }

// GetFSBase gets the current %FS.base value.
inline uint64_t GetFSBase() { return _readfsbase_u64(); }

// CPURelax inserts a pause during busy polling.
inline void CPURelax() { __builtin_ia32_pause(); }

// SetUIF enables user interrupts.
inline void SetUIF() { __builtin_ia32_stui(); }

// ClearUIF disables user interrupts.
inline void ClearUIF() { __builtin_ia32_clui(); }

// TestUIF returns true if user interrupts are enabled.
inline bool TestUIF() { return __builtin_ia32_testui(); }

// XSave structures
struct xstate_header {
  uint64_t xstate_bv;
  uint64_t xcomp_bv;
  uint64_t reserved[6];
};

struct fpstate_64 {
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
  uint64_t sw_reserved[6];
};

struct xstate {
  struct fpstate_64 fpstate;
  struct xstate_header xstate_hdr;
  unsigned char xsave_area[];
};

static_assert(offsetof(xstate, xstate_hdr) == 512);

inline bool CPUHasPKUSupport() {
  cpuid_info regs;
  cpuid(0x7, 0, &regs);
  return (regs.ecx & BIT(3)) > 0;
}

// XSaveCompact saves the set of extended CPU states specified in @features into
// @buf using the compacted format. It uses the init optimization to avoid
// saving states that are not in use.
inline __nofp void XSaveCompact(void *buf, uint64_t features, size_t size) {
  assert((uintptr_t)buf % kXsaveAlignment == 0);
  xstate *x = reinterpret_cast<xstate *>(buf);
  // Zero the xsave header.
  __builtin_memset(&x->xstate_hdr, 0, sizeof(x->xstate_hdr));
  __builtin_ia32_xsavec64(buf, features);
  // Stash the size.
  x->fpstate.sw_reserved[0] = size;
}

[[nodiscard]] __nofp __always_inline size_t GetXSaveSize(void *buf) {
  assert(buf);
  xstate *x = reinterpret_cast<xstate *>(buf);
  return x->fpstate.sw_reserved[0];
}

// XSave saves the set of extended CPU states specified in @features into
// @buf with no optimizations.
inline __nofp void XSave(void *buf, uint64_t features) {
  assert((uintptr_t)buf % kXsaveAlignment == 0);
  __builtin_ia32_xsave64(buf, features);
}

// XSaveOpt saves the set of extended CPU states specified in @features into
// @buf using the modified optimization to avoid saving states that have not
// been modified since the last xrstor. This should only be used with a @buf
// that was created with XSave and used for the last XRestore.
inline __nofp void XSaveOpt(void *buf, uint64_t features) {
  assert((uintptr_t)buf % kXsaveAlignment == 0);
  __builtin_ia32_xsaveopt64(buf, features);
}

// XRestore restores the set of extended CPU states saved in @buf.
inline __nofp void XRestore(void *buf) {
  assert((uintptr_t)buf % kXsaveAlignment == 0);
  xstate *x = reinterpret_cast<xstate *>(buf);
  __builtin_ia32_xrstor64(buf, x->xstate_hdr.xstate_bv);
}

inline __nofp uint64_t GetActiveXstates() { return __builtin_ia32_xgetbv(1); }

// Send a user IPI to @cpu.
inline void SendUipi(unsigned int cpu) { __builtin_ia32_senduipi(cpu); }

// ReadRandom gets random bytes from the hardware RNG (fast).
Status<size_t> ReadRandom(std::span<std::byte> buf);

// ReadEntropy gets random bytes from the hardware entropy source (slow).
Status<size_t> ReadEntropy(std::span<std::byte> buf, bool blocking = true);

}  // namespace junction
