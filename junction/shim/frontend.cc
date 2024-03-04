
extern "C" {
#include <pthread.h>
}

#include "junction/bindings/sync.h"
#include "junction/shim/shim.h"
#include "junction/shim/sync.h"

#define MUTEX_BACKEND_CALL(nn)                                                 \
  {                                                                            \
    auto fn = reinterpret_cast<decltype(nn) **>(0x202000 +                     \
                                                8 * junction::CallNumber::nn); \
    auto ret = (*fn)(mutex);                                                   \
    if (__builtin_expect((ret) < 0, 0)) {                                      \
      errno = -(ret);                                                          \
      return -1;                                                               \
    }                                                                          \
    return ret;                                                                \
  }

#define MUTEX_BACKEND_CALL_RET0(nn)                                            \
  {                                                                            \
    auto fn = reinterpret_cast<decltype(nn) **>(0x202000 +                     \
                                                8 * junction::CallNumber::nn); \
    (*fn)(mutex);                                                              \
    return 0;                                                                  \
  }

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  junction::ShimMutex *sm = junction::ShimMutex::fromPthreadNoCheck(mutex);
  if (likely(atomic_cmpxchg(&sm->mutex.held, 1, 0))) return 0;

  MUTEX_BACKEND_CALL_RET0(pthread_mutex_unlock);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
  junction::ShimMutex *sm = junction::ShimMutex::fromPthreadNoCheck(mutex);
  if (likely(sm->init_magic == kInitMagic)) {
    return mutex_try_lock(&sm->mutex) ? 0 : EBUSY;
  }

  MUTEX_BACKEND_CALL(pthread_mutex_trylock);
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
  junction::ShimMutex *sm = junction::ShimMutex::fromPthreadNoCheck(mutex);
  if (likely(sm->init_magic == kInitMagic && mutex_try_lock(&sm->mutex)))
    return 0;

  MUTEX_BACKEND_CALL_RET0(pthread_mutex_lock);
}