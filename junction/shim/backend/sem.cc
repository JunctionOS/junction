
#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"

extern "C" {
#include <base/list.h>
#include <semaphore.h>

#include "lib/caladan/runtime/defs.h"
}

#include "junction/shim/shim.h"

namespace junction {

struct ShimSem {
  rt::Spin lock;
  unsigned int value;
  list_head waiters;

  ShimSem(unsigned int value) : value(value) { list_head_init(&waiters); }
  ~ShimSem() { assert(list_empty(&waiters)); }
};

static_assert(sizeof(sem_t) >= sizeof(ShimSem));

int shim_sem_init(sem_t *__sem, int __pshared, unsigned int __value) {
  if (__pshared) {
    LOG(WARN) << "No shim support for shared semaphores";
    return -ENOSYS;
  }

  new (__sem) ShimSem(__value);
  return 0;
}

/* Free resources associated with semaphore object SEM.  */
int shim_sem_destroy(sem_t *__sem) {
  ShimSem *s = reinterpret_cast<ShimSem *>(__sem);
  std::destroy_at(s);
  return 0;
}

/* Open a named semaphore NAME with open flags OFLAG.  */
sem_t *shim_sem_open(const char *__name, int __oflag, va_list *args) {
  LOG(WARN) << "No shim support for sem_open";
  return reinterpret_cast<sem_t *>(-ENOSYS);
}

/* Close descriptor for named semaphore SEM.  */
int shim_sem_close(sem_t *__sem) {
  LOG(WARN) << "No shim support for sem_close";
  return -ENOSYS;
}

/* Remove named semaphore NAME.  */
int shim_sem_unlink(const char *__name) {
  LOG(WARN) << "No shim support for sem_unlink";
  return -ENOSYS;
}

/* Wait for SEM being posted.
    This function is a cancellation point and therefore not marked with
    __THROW.  */
int shim_sem_wait(sem_t *__sem) {
  ShimSem *s = reinterpret_cast<ShimSem *>(__sem);

  s->lock.Lock();
  if (s->value > 0) {
    s->value--;
    s->lock.Unlock();
    return 0;
  }

  thread_t *myth = thread_self();
  list_add_tail(&s->waiters, &myth->link);
  s->lock.UnlockAndPark();
  return 0;
}

int shim_sem_clockwait(sem_t *__restrict __sem, clockid_t clock,
                       const struct timespec *__restrict __abstime) {
  LOG(WARN) << "No shim support for sem_clockwait";
  return -ENOSYS;
}

/* Test whether SEM is posted.  */
int shim_sem_trywait(sem_t *__sem) {
  ShimSem *s = reinterpret_cast<ShimSem *>(__sem);

  bool success = false;
  s->lock.Lock();
  if (s->value > 0) {
    s->value--;
    success = true;
  }
  s->lock.Unlock();
  if (success) return 0;
  return -EAGAIN;
}

/* Post SEM.  */
int shim_sem_post(sem_t *__sem) {
  ShimSem *s = reinterpret_cast<ShimSem *>(__sem);

  s->lock.Lock();
  thread_t *waketh = list_pop(&s->waiters, thread_t, link);
  if (waketh)
    assert(s->value == 0);
  else
    s->value++;
  s->lock.Unlock();

  if (waketh) thread_ready(waketh);

  return 0;
}

/* Get current value of SEM and store it in *SVAL.  */
int shim_sem_getvalue(sem_t *__restrict __sem, int *__restrict __sval) {
  ShimSem *s = reinterpret_cast<ShimSem *>(__sem);

  s->lock.Lock();
  *__sval = s->value;
  s->lock.Unlock();
  return 0;
}

}  // namespace junction
