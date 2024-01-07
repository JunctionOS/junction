// arch.h - x86 constants and utilities

#pragma once

#include <immintrin.h>

#include <span>

#include "junction/base/bits.h"
#include "junction/base/error.h"

namespace junction {

inline constexpr size_t kPageSize = 4096;
inline constexpr size_t kLargePageSize = 2097152;
inline constexpr size_t kCacheLineSize = 64;
inline constexpr size_t kXsaveAlignment = 64;
inline constexpr size_t kXsaveHeaderOffset = 512;
inline constexpr size_t kXsaveHeaderSize = 64;

// PageAlign aligns an address upward to the nearest page size
template <typename T>
constexpr T PageAlign(T addr)
  requires std::is_unsigned_v<T>
{
  return AlignUp(addr, kPageSize);
}

// PageAlignDown aligns an address downward to the nearest page size
template <typename T>
constexpr T PageAlignDown(T addr)
  requires std::is_unsigned_v<T>
{
  return AlignDown(addr, kPageSize);
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

// XSaveCompact saves the set of extended CPU states specified in @features into
// @buf.
inline __nofp void XSaveCompact(void *buf, uint64_t features) {
  assert((uintptr_t)buf % kXsaveAlignment == 0);
  // Zero the xsave header
  __builtin_memset(reinterpret_cast<std::byte *>(buf) + kXsaveHeaderOffset, 0,
                   kXsaveHeaderSize);
  __builtin_ia32_xsavec64(buf, features);
}

// XRestore restores the set of extended CPU states specified in @features from
// @buf.
inline __nofp void XRestore(void *buf, uint64_t features) {
  assert((uintptr_t)buf % kXsaveAlignment == 0);
  __builtin_ia32_xrstor64(buf, features);
}

// Send a user IPI to @cpu.
inline void SendUipi(unsigned int cpu) { __builtin_ia32_senduipi(cpu); }

// ReadRandom gets random bytes from the hardware RNG (fast).
Status<size_t> ReadRandom(std::span<std::byte> buf);

// ReadEntropy gets random bytes from the hardware entropy source (slow).
Status<size_t> ReadEntropy(std::span<std::byte> buf, bool blocking = true);

}  // namespace junction
