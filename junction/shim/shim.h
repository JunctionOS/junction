// shim.h - this file is included in both the preload library and the internal
// shim backend. Don't include junction-specific headers in this file

#pragma once

#include <cstdarg>
#include <cstddef>

extern "C" {
#include <pthread.h>
#include <semaphore.h>
}

#define SHIMCALL_JMPTBL_LOC (0x202000UL)

struct stack;

namespace junction {

struct CallNumber {
  enum : size_t {
    allocate_stack = 0,     /* KEEP AT 0 */
    free_stack = 1,         /* KEEP AT 1 */
    free_stack_on_exit = 2, /* KEEP AT 2 */
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
    sem_init,
    sem_destroy,
    sem_open,
    sem_close,
    sem_unlink,
    sem_wait,
    sem_clockwait,
    sem_trywait,
    sem_post,
    sem_getvalue,
    NR_SHIM_CALL  // must be last
  };
};

extern "C" {

int shim_allocate_stack(void **stack_bottom_out, size_t *stack_size_out,
                        size_t *guard_size_out);
void shim_free_stack(void *stack_top);
void shim_free_stack_on_exit(void *stack_top);

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

int shim_sem_init(sem_t *__sem, int __pshared, unsigned int __value);
int shim_sem_destroy(sem_t *__sem);
sem_t *shim_sem_open(const char *__name, int __oflag, va_list *args);
int shim_sem_close(sem_t *__sem);
int shim_sem_unlink(const char *__name);
int shim_sem_wait(sem_t *__sem);
int shim_sem_clockwait(sem_t *__restrict __sem, clockid_t clock,
                       const struct timespec *__restrict __abstime);
int shim_sem_trywait(sem_t *__sem);
int shim_sem_post(sem_t *__sem);
int shim_sem_getvalue(sem_t *__restrict __sem, int *__restrict __sval);

extern void *shim_jmptbl[static_cast<size_t>(CallNumber::NR_SHIM_CALL)];
}

}  // namespace junction
