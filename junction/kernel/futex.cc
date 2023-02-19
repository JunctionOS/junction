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

Status<void> FutexTable::Wait(uint32_t *key, uint32_t val, uint32_t bitset,
                              std::optional<uint64_t> timeout_us) {
  detail::futex_waiter waiter{thread_self(), key, bitset};
  detail::futex_bucket &bucket = get_bucket(key);

  // Setup a timer for the timeout (if needed).
  rt::Timer timer([&bucket, &waiter] {
    rt::SpinGuard g(bucket.lock);
    if (waiter.th) {
      bucket.futexes.erase(decltype(bucket.futexes)::s_iterator_to(waiter));
      // Must remove the waiter from the list *before* waking it
      thread_ready(waiter.th);
    }
  });
  if (timeout_us) timer.Start(*timeout_us);

  // Wait for a wakeup.
  bucket.lock.Lock();
  if (read_once(*key) != val) {
    bucket.lock.Unlock();
    timer.Cancel();
    return MakeError(EAGAIN);
  }
  bucket.futexes.push_back(waiter);
  bucket.lock.UnlockAndPark();

  // Cancel the timer if pending and return.
  timer.Cancel();
  if (waiter.th) return MakeError(ETIMEDOUT);
  return {};
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

constexpr bool FutexCmdHasTimeout(uint32_t cmd) {
  switch (cmd) {
    case FUTEX_WAIT:
    case FUTEX_LOCK_PI:
    case FUTEX_LOCK_PI2:
    case FUTEX_WAIT_BITSET:
    case FUTEX_WAIT_REQUEUE_PI:
      return true;
  }
  return false;
}

long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3) {
  futex_op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
  FutexTable &t = FutexTable::GetFutexTable();
  std::optional<uint64_t> timeout_us;
  if (timeout && FutexCmdHasTimeout(futex_op))
    timeout_us = timespec_to_us(*timeout);
  Status<void> ret;

  switch (futex_op) {
    case FUTEX_WAKE:
      return t.Wake(uaddr, val, kFutexBitsetAny);
    case FUTEX_WAKE_BITSET:
      return t.Wake(uaddr, val, val3);
    case FUTEX_WAIT:
      ret = t.Wait(uaddr, val, kFutexBitsetAny, timeout_us);
      if (!ret) return MakeCError(ret);
      break;
    case FUTEX_WAIT_BITSET:
      ret = t.Wait(uaddr, val, val3, timeout_us);
      if (!ret) return MakeCError(ret);
      break;
    default:
      return -ENOSYS;
  }

  return 0;
}

}  // namespace junction
