// arch.h - x86 constants and utilities

#pragma once

#include <immintrin.h>

#include <span>

#include "junction/base/bits.h"
#include "junction/base/error.h"

namespace junction {

constexpr size_t kPageSize = 4096;
constexpr size_t kLargePageSize = 2097152;
constexpr size_t kCacheLineSize = 64;

// PageAlign aligns an address upward to the nearest page size
template <typename T>
constexpr T PageAlign(T addr) requires std::is_unsigned_v<T> {
  return AlignUp(addr, kPageSize);
}

// PageAlignDown aligns an address downward to the nearest page size
template <typename T>
constexpr T PageAlignDown(T addr) requires std::is_unsigned_v<T> {
  return AlignDown(addr, kPageSize);
}

// SetFSBase sets the %FS.base value.
inline void SetFSBase(uint64_t val) { _writefsbase_u64(val); }

// GetFSBase gets the current %FS.base value.
inline uint64_t GetFSBase() { return _readfsbase_u64(); }

// ReadRandom gets random bytes from the hardware RNG.
Status<size_t> ReadRandom(std::span<std::byte> buf);

}  // namespace junction
