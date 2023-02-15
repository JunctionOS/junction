// futex.cc - support for futex synchronization

extern "C" {
#include <linux/futex.h>
}

#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/futex.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/time.h"
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

Status<void> FutexTable::WaitOrTimeout(uint32_t *key, uint32_t val,
                                       uint32_t bitset, uint64_t timeout_us) {
  detail::futex_waiter waiter{thread_self(), key, bitset};
  detail::futex_bucket &bucket = get_bucket(key);

  // Setup a timeout (if needed).
  rt::Timer timer([&bucket, &waiter] {
    rt::SpinGuard g(bucket.lock);
    if (waiter.th) {
      bucket.futexes.erase(decltype(bucket.futexes)::s_iterator_to(waiter));
      // Must remove the waiter from the list *before* waking it
      thread_ready(waiter.th);
    }
  });
  timer.Start(timeout_us);

  bucket.lock.Lock();
  if (rt::read_once(*key) != val) {
    bucket.lock.Unlock();
    return MakeError(EAGAIN);
  }

  bucket.futexes.push_back(waiter);
  bucket.lock.UnlockAndPark();

  if (!waiter.th) {
    timer.Cancel();
    return {};
  }
  return MakeError(ETIMEDOUT);
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
    thread_t *th = std::exchange(w.th, nullptr);
    it = bucket.futexes.erase(it);
    thread_ready(th);
    if (++i >= n) break;
  }
  return i;
}

long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3) {
  futex_op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
  FutexTable &t = FutexTable::GetFutexTable();

  switch (futex_op) {
    case FUTEX_WAKE:
      return t.Wake(uaddr, val, kFutexBitsetAny);
    case FUTEX_WAKE_BITSET:
      return t.Wake(uaddr, val, val3);
    case FUTEX_WAIT:
      if (timeout) {
        Status<void> ret = t.WaitOrTimeout(uaddr, val, kFutexBitsetAny,
                                           timespec_to_us(*timeout));
        if (!ret) return MakeCError(ret);
        break;
      }
      if (!t.Wait(uaddr, val, kFutexBitsetAny)) return -EAGAIN;
      break;
    case FUTEX_WAIT_BITSET:
      if (timeout) {
        Status<void> ret =
            t.WaitOrTimeout(uaddr, val, val3, timespec_to_us(*timeout));
        if (!ret) return MakeCError(ret);
        break;
      }
      if (!t.Wait(uaddr, val, val3)) return -EAGAIN;
      break;
    default:
      return -ENOSYS;
  }

  return 0;
}

}  // namespace junction
