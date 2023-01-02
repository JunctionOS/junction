// futex.cc - support for futex synchronization

extern "C" {
#include <linux/futex.h>
}

#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/kernel/futex.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

FutexTable &FutexTable::GetFutexTable() {
  static FutexTable f;
  return f;
}

bool FutexTable::Wait(uint32_t *key, uint32_t val, uint32_t bitset) {
  detail::futex_waiter waiter{thread_self(), key, bitset};
  detail::futex_bucket &bucket = get_bucket(key);
  bucket.lock.Lock();
  if (rt::read_once(*key) != val) {
    bucket.lock.Unlock();
    return false;
  }

  bucket.futexes.push_back(waiter);
  bucket.lock.UnlockAndPark();
  return true;
}

int FutexTable::Wake(uint32_t *key, int n, uint32_t bitset) {
  if (unlikely(n == 0)) return 0;
  detail::futex_bucket &bucket = get_bucket(key);
  int i = 0;
  rt::SpinGuard g(bucket.lock);
  for (auto it = bucket.futexes.begin(); it != bucket.futexes.end();) {
    detail::futex_waiter &w = *it;
    if (w.key != key || !(w.bitset & bitset)) {
      ++it;
      continue;
    }

    // Must remove the waiter from the list *before* waking it
    thread_t *th = w.th;
    it = bucket.futexes.erase(it);
    thread_ready(th);
    if (++i >= n) break;
  }
  return i;
}

long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3) {
  if (timeout) LOG_ONCE(WARN) << "Futex timeout not supported";

  futex_op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
  FutexTable &t = FutexTable::GetFutexTable();

  switch (futex_op) {
    case FUTEX_WAKE:
      return t.Wake(uaddr, val, kFutexBitsetAny);
    case FUTEX_WAKE_BITSET:
      return t.Wake(uaddr, val, val3);
    case FUTEX_WAIT:
      if (!t.Wait(uaddr, val, kFutexBitsetAny)) return -EAGAIN;
      break;
    case FUTEX_WAIT_BITSET:
      if (!t.Wait(uaddr, val, val3)) return -EAGAIN;
      break;
    default:
      return -ENOSYS;
  }

  return 0;
}

}  // namespace junction
