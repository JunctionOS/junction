#pragma once

extern "C" {
#include <pthread.h>
#include <sys/time.h>
}

#include <new>

#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/shim/shim.h"

inline constexpr uint32_t kInitMagic = 0xDEADBEEF;

namespace junction {

namespace {

struct ShimMutex {
  uint32_t init_magic{kInitMagic};
  mutex_t mutex;
  ShimMutex() { mutex_init(&mutex); }
  ~ShimMutex() { assert(!mutex_held(&mutex)); }
  static inline void InitCheck(ShimMutex *m) {
    if (unlikely(m->init_magic != kInitMagic)) new (m) ShimMutex();
  }
  static inline ShimMutex *fromPthread(pthread_mutex_t *m) {
    ShimMutex *sm = reinterpret_cast<ShimMutex *>(m);
    InitCheck(sm);
    return sm;
  }
  static inline ShimMutex *fromPthreadNoCheck(pthread_mutex_t *m) {
    ShimMutex *sm = reinterpret_cast<ShimMutex *>(m);
    return sm;
  }
};

}  // namespace

}  // namespace junction
