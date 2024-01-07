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

// CPURelax inserts a pause during busy polling
inline void CPURelax() { __builtin_ia32_pause(); }

// ReadRandom gets random bytes from the hardware RNG (fast).
Status<size_t> ReadRandom(std::span<std::byte> buf);

// ReadEntropy gets random bytes from the hardware entropy source (slow).
Status<size_t> ReadEntropy(std::span<std::byte> buf, bool blocking = true);

}  // namespace junction
