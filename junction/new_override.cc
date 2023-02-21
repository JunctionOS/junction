// new_override.cc - overrides the default C++ memory allocator

extern "C" {
#include <base/page.h>
#include <runtime/smalloc.h>
}

#include <cstdlib>
#include <memory>

#include "junction/base/arch.h"
#include "junction/bindings/runtime.h"
#include "junction/kernel/ksys.h"

namespace junction {

// The maximum size in bytes supported by smalloc()
constexpr size_t kMaxAllocSize = (1UL << 18);  // 256 KB

// indicates whether the runtime is initialized enough to use its allocator
// cache aligned to prevent false sharing
struct alignas(kCacheLineSize) {
  bool ready;
} runtime;

void *do_new(size_t size) {
  // Handle the case where the runtime is not initialized
  if (unlikely(!runtime.ready)) return std::malloc(size);

  // Handle the case where the object being allocated is large
  if (unlikely(size > kMaxAllocSize)) {
    rt::RuntimeLibcGuard guard;
    return std::malloc(size);
  }

  // Hot path: Handle typical allocations using the runtime
  return smalloc(size);
}

void *do_new_aligned(size_t size, std::align_val_t a) {
  auto align = static_cast<size_t>(a);

  // Handle the case where the runtime is not initialized
  if (unlikely(!runtime.ready)) return std::aligned_alloc(size, align);

  // Handle the case where the object being allocated is large
  if (unlikely(size >= kMaxAllocSize)) {
    rt::RuntimeLibcGuard guard;
    return std::aligned_alloc(size, align);
  }

  // Hot path: Handle typical allocations using the runtime
  return smalloc(AlignUp(size, align));
}

void do_free(void *ptr) {
  // Hot path: free memory using the runtine
  if (likely(is_page_addr(ptr))) {
    sfree(ptr);
    return;
  }

  // Otherwise free using libc.
  if (likely(runtime.ready)) {
    rt::RuntimeLibcGuard guard;
    std::free(ptr);
  }

  // But call directly if the runtime is not initialized yet.
  std::free(ptr);
}

void EnableMemoryAllocation() { runtime.ready = true; }

}  // namespace junction

//
// Override global new and delete operators
//

void *operator new(size_t size, const std::nothrow_t &tag) noexcept {
  return junction::do_new(size);
}

void *operator new[](size_t size, const std::nothrow_t &tag) noexcept {
  return junction::do_new(size);
}

void *operator new(size_t size, std::align_val_t align,
                   const std::nothrow_t &tag) noexcept {
  return junction::do_new_aligned(size, align);
}

void *operator new[](size_t size, std::align_val_t align,
                     const std::nothrow_t &tag) noexcept {
  return junction::do_new_aligned(size, align);
}

void *operator new(size_t size) throw() {
  void *ptr = junction::do_new(size);
  if (unlikely(size > 0 && !ptr)) throw std::bad_alloc();
  return ptr;
}

void *operator new[](size_t size) throw() {
  void *ptr = junction::do_new(size);
  if (unlikely(size > 0 && !ptr)) throw std::bad_alloc();
  return ptr;
}

void *operator new(size_t size, std::align_val_t align) throw() {
  void *ptr = junction::do_new_aligned(size, align);
  if (unlikely(size > 0 && !ptr)) throw std::bad_alloc();
  return ptr;
}

void *operator new[](size_t size, std::align_val_t align) throw() {
  void *ptr = junction::do_new_aligned(size, align);
  if (unlikely(size > 0 && !ptr)) throw std::bad_alloc();
  return ptr;
}

void operator delete(void *ptr) noexcept {
  if (unlikely(!ptr)) return;
  junction::do_free(ptr);
}

void operator delete[](void *ptr) noexcept {
  if (unlikely(!ptr)) return;
  junction::do_free(ptr);
}

void operator delete(void *ptr, std::align_val_t align) noexcept {
  if (unlikely(!ptr)) return;
  junction::do_free(ptr);
}
