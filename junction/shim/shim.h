// shim.h - this file is included in both the preload library and the internal
// shim backend. Don't include junction-specific headers in this file

#pragma once

#include <cstddef>

extern "C" {
#include <pthread.h>
}

#define SHIMCALL_JMPTBL_LOC (0x202000UL)

struct stack;

namespace junction {

struct CallNumber {
  enum : size_t {
    allocate_stack = 0,
    free_stack,
    pthread_rwlock_destroy,
    pthread_rwlock_init,
    pthread_rwlock_rdlock,
    pthread_rwlock_tryrdlock,
    pthread_rwlock_trywrlock,
    pthread_rwlock_wrlock,
    pthread_rwlock_unlock,
    pthread_barrier_init,
    pthread_barrier_wait,
    pthread_barrier_destroy,
    pthread_cond_init,
    pthread_cond_signal,
    pthread_cond_broadcast,
    pthread_cond_wait,
    pthread_cond_timedwait,
    pthread_cond_destroy,
    pthread_mutex_init,
    pthread_mutex_lock,
    pthread_mutex_trylock,
    pthread_mutex_unlock,
    pthread_mutex_destroy,
    NR_SHIM_CALL
  };
};

extern "C" {

// function calls
extern stack *allocate_stack();
extern void free_stack(stack *stack);

extern stack *shim_allocate_stack();
extern void shim_free_stack(stack *stack);

int shim_pthread_mutex_init(pthread_mutex_t *mutex,
                            const pthread_mutexattr_t *mutexattr);
int shim_pthread_mutex_lock(pthread_mutex_t *mutex);
int shim_pthread_mutex_trylock(pthread_mutex_t *mutex);
int shim_pthread_mutex_unlock(pthread_mutex_t *mutex);
int shim_pthread_mutex_destroy(pthread_mutex_t *mutex);
int shim_pthread_barrier_init(pthread_barrier_t *__restrict barrier,
                              const pthread_barrierattr_t *__restrict attr,
                              unsigned count);
int shim_pthread_barrier_wait(pthread_barrier_t *barrier);
int shim_pthread_barrier_destroy(pthread_barrier_t *barrier);
int shim_pthread_cond_init(pthread_cond_t *__restrict cond,
                           const pthread_condattr_t *__restrict cond_attr);
int shim_pthread_cond_signal(pthread_cond_t *cond);
int shim_pthread_cond_broadcast(pthread_cond_t *cond);
int shim_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int shim_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                const struct timespec *abstime);
int shim_pthread_cond_destroy(pthread_cond_t *cond);
int shim_pthread_cond_destroy(pthread_cond_t *cond);
int shim_pthread_rwlock_destroy(pthread_rwlock_t *r);
int shim_pthread_rwlock_init(pthread_rwlock_t *r,
                             const pthread_rwlockattr_t *attr);
int shim_pthread_rwlock_rdlock(pthread_rwlock_t *r);
int shim_pthread_rwlock_tryrdlock(pthread_rwlock_t *r);
int shim_pthread_rwlock_trywrlock(pthread_rwlock_t *r);
int shim_pthread_rwlock_wrlock(pthread_rwlock_t *r);
int shim_pthread_rwlock_unlock(pthread_rwlock_t *r);

extern void *shim_jmptbl[static_cast<size_t>(CallNumber::NR_SHIM_CALL)];
}

}  // namespace junction
