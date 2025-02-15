#pragma once

extern "C" {
extern const unsigned char __libvdso_start[];
extern const unsigned char __libvdso_end[];
}

namespace junction {

inline size_t vdso_size() { return __libvdso_end - __libvdso_start; }

inline unsigned char *vdso_initial_location() {
  return const_cast<unsigned char *>(&__libvdso_start[0]);
}

inline constexpr uintptr_t kVDSOLocation = 0x201000;

}  // namespace junction
