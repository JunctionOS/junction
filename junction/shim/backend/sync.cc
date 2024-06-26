
extern "C" {
#include <pthread.h>
#include <sys/time.h>
}

#include <new>

#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/shim/shim.h"
#include "junction/shim/sync.h"

namespace junction {

namespace {

inline constexpr uint32_t kInitMagic = 0xDEADBEEF;

struct ShimCondVar {
  uint32_t init_magic{kInitMagic};
  ShimCondVar() { condvar_init(&cv); }
  condvar_t cv;
  clockid_t clockid;
  static inline void InitCheck(ShimCondVar *cv) {
    if (unlikely(cv->init_magic != kInitMagic)) new (cv) ShimCondVar();
  }
  static inline ShimCondVar *fromPthread(pthread_cond_t *m) {
    ShimCondVar *sm = reinterpret_cast<ShimCondVar *>(m);
    InitCheck(sm);
    return sm;
  }
};

struct ShimRWMutex {
  uint32_t init_magic{kInitMagic};
  rt::SharedMutex rwmutex;
  static inline void InitCheck(ShimRWMutex *m) {
    if (unlikely(m->init_magic != kInitMagic)) new (m) ShimRWMutex();
  }
  static inline ShimRWMutex *fromPthread(pthread_rwlock_t *m) {
    ShimRWMutex *sm = reinterpret_cast<ShimRWMutex *>(m);
    InitCheck(sm);
    return sm;
  }
};

#if 0
struct ShimBarrier {
  rt::Latch br;
  ShimBarrier(int count) : br(count) {}
  static inline ShimBarrier *fromPthread(pthread_barrier_t *m) {
    return reinterpret_cast<ShimBarrier *>(m);
  }
};

static_assert(sizeof(pthread_barrier_t) >= sizeof(ShimBarrier));
#endif
static_assert(sizeof(pthread_mutex_t) >= sizeof(ShimMutex));
static_assert(sizeof(pthread_cond_t) >= sizeof(ShimCondVar));
static_assert(sizeof(pthread_rwlock_t) >= sizeof(ShimRWMutex));

}  // namespace

int shim_pthread_mutex_init(pthread_mutex_t *mutex,
                            const pthread_mutexattr_t *mutexattr) {
  ShimMutex::fromPthread(mutex);
  return 0;
}

int shim_pthread_mutex_lock(pthread_mutex_t *mutex) {
  ShimMutex *m = ShimMutex::fromPthread(mutex);
  __mutex_lock(&m->mutex);
  return 0;
}

int shim_pthread_mutex_trylock(pthread_mutex_t *mutex) {
  ShimMutex *m = ShimMutex::fromPthread(mutex);
  return mutex_try_lock(&m->mutex) ? 0 : EBUSY;
}

int shim_pthread_mutex_unlock(pthread_mutex_t *mutex) {
  ShimMutex *m = ShimMutex::fromPthreadNoCheck(mutex);
  __mutex_unlock(&m->mutex);
  return 0;
}

int shim_pthread_mutex_destroy(pthread_mutex_t *mutex) {
  ShimMutex *m = ShimMutex::fromPthread(mutex);
  std::destroy_at(m);
  return 0;
}

#if 0
int shim_pthread_barrier_init(pthread_barrier_t *__restrict barrier,
                              const pthread_barrierattr_t *__restrict attr,
                              unsigned count) {
  ShimBarrier *b = ShimBarrier::fromPthread(barrier);
  new (b) ShimBarrier(count);
  return 0;
}

int shim_pthread_barrier_wait(pthread_barrier_t *barrier) {
  ShimBarrier *b = ShimBarrier::fromPthread(barrier);

  bool serial_thread;
  // TODO: handle interruptible part
  b->br.POSIXWaitInterruptible(&serial_thread);
  if (serial_thread) return PTHREAD_BARRIER_SERIAL_THREAD;
  return 0;
}

int shim_pthread_barrier_destroy(pthread_barrier_t *barrier) {
  ShimBarrier *b = ShimBarrier::fromPthread(barrier);
  std::destroy_at(b);
  return 0;
}
#endif

int shim_pthread_cond_init(pthread_cond_t *__restrict cond,
                           const pthread_condattr_t *__restrict cond_attr) {
  ShimCondVar *c = ShimCondVar::fromPthread(cond);

  if (!cond_attr || pthread_condattr_getclock(cond_attr, &c->clockid)) {
    c->clockid = CLOCK_REALTIME;
  }
  return 0;
}

int shim_pthread_cond_signal(pthread_cond_t *cond) {
  ShimCondVar *c = ShimCondVar::fromPthread(cond);
  condvar_signal(&c->cv);
  return 0;
}

int shim_pthread_cond_broadcast(pthread_cond_t *cond) {
  ShimCondVar *c = ShimCondVar::fromPthread(cond);
  condvar_broadcast(&c->cv);
  return 0;
}

int shim_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
  ShimCondVar *c = ShimCondVar::fromPthread(cond);
  ShimMutex *m = ShimMutex::fromPthread(mutex);
  condvar_wait(&c->cv, &m->mutex);

  return 0;
}

int shim_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                const struct timespec *abstime) {
  ShimCondVar *c = ShimCondVar::fromPthread(cond);
  ShimMutex *m = ShimMutex::fromPthread(mutex);

  timespec now_ts;
  BUG_ON(clock_gettime(c->clockid, &now_ts));

  uint64_t wait_us = abstime->tv_sec * kSeconds + abstime->tv_nsec / 1000;
  uint64_t now_us = now_ts.tv_sec * kSeconds + now_ts.tv_nsec / 1000;

  if (wait_us <= now_us) return ETIMEDOUT;
  bool done = condvar_wait_timed(&c->cv, &m->mutex, wait_us - now_us);
  return done ? 0 : ETIMEDOUT;
}

int shim_pthread_cond_destroy(pthread_cond_t *cond) {
  ShimCondVar *c = ShimCondVar::fromPthread(cond);
  std::destroy_at(c);
  return 0;
}

int shim_pthread_rwlock_destroy(pthread_rwlock_t *r) {
  ShimRWMutex *rw = ShimRWMutex::fromPthread(r);
  std::destroy_at(rw);
  return 0;
}

int shim_pthread_rwlock_init(pthread_rwlock_t *r,
                             const pthread_rwlockattr_t *attr) {
  ShimRWMutex::fromPthread(r);
  return 0;
}

int shim_pthread_rwlock_rdlock(pthread_rwlock_t *r) {
  ShimRWMutex *rw = ShimRWMutex::fromPthread(r);
  rw->rwmutex.LockShared();
  return 0;
}

int shim_pthread_rwlock_tryrdlock(pthread_rwlock_t *r) {
  ShimRWMutex *rw = ShimRWMutex::fromPthread(r);
  return rw->rwmutex.TryLockShared() ? 0 : EBUSY;
}

int shim_pthread_rwlock_trywrlock(pthread_rwlock_t *r) {
  ShimRWMutex *rw = ShimRWMutex::fromPthread(r);
  return rw->rwmutex.TryLock() ? 0 : EBUSY;
}

int shim_pthread_rwlock_wrlock(pthread_rwlock_t *r) {
  ShimRWMutex *rw = ShimRWMutex::fromPthread(r);
  rw->rwmutex.Lock();
  return 0;
}

int shim_pthread_rwlock_unlock(pthread_rwlock_t *r) {
  ShimRWMutex *rw = ShimRWMutex::fromPthread(r);
  assert(rw->rwmutex.IsHeld());
  if (rw->rwmutex.IsHeldShared()) {
    rw->rwmutex.UnlockShared();
  } else {
    rw->rwmutex.Unlock();
  }
  return 0;
}

}  // namespace junction
