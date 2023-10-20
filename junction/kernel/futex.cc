// futex.cc - support for futex synchronization

extern "C" {
#include <linux/futex.h>
}

#include "junction/base/finally.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/bindings/wait.h"
#include "junction/kernel/futex.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

static FutexTable f;

FutexTable &FutexTable::GetFutexTable() { return f; }

Status<void> FutexTable::Wait(uint32_t *key, uint32_t val, uint32_t bitset,
                              std::optional<Time> timeout) {
  // Hot path: Don't need to block for a false condition.
  if (read_once(*key) != val) return MakeError(EAGAIN);

  detail::futex_bucket &bucket = get_bucket(key);

  rt::ThreadWaker w;
  WakeOnTimeout timed_out(bucket.lock, w, timeout);
  WakeOnSignal signaled(bucket.lock);
  detail::futex_waiter waiter{&w, key, bitset};

  {
    rt::SpinGuard g(bucket.lock);

    if (read_once(*key) != val) return MakeError(EAGAIN);

    bucket.futexes.push_back(waiter);
    g.Park(w, [&waiter, &timed_out, &signaled] {
      return !waiter.waker || timed_out || signaled;
    });

    if (waiter.waker)
      bucket.futexes.erase(decltype(bucket.futexes)::s_iterator_to(waiter));
  }

  if (!waiter.waker) return {};

  assert(signaled || timed_out);
  return signaled ? MakeError(EINTR) : MakeError(ETIMEDOUT);
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
    rt::ThreadWaker *waker = std::exchange(w.waker, nullptr);
    it = bucket.futexes.erase(it);
    waker->Wake();
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
                const struct timespec *ts, uint32_t *uaddr2, uint32_t val3) {
  futex_op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
  FutexTable &t = FutexTable::GetFutexTable();
  std::optional<Time> timeout;
  Status<void> ret;

  switch (futex_op) {
    case FUTEX_WAKE:
      return t.Wake(uaddr, val, kFutexBitsetAny);
    case FUTEX_WAKE_BITSET:
      return t.Wake(uaddr, val, val3);
    case FUTEX_WAIT:
      if (ts) timeout = Time::Now() + Duration(*ts);
      ret = t.Wait(uaddr, val, kFutexBitsetAny, timeout);
      if (!ret) return MakeCError(ret);
      break;
    case FUTEX_WAIT_BITSET:
      if (ts) timeout = Time::FromUnixTime(*ts);
      ret = t.Wait(uaddr, val, val3, timeout);
      if (!ret) return MakeCError(ret);
      break;
    default:
      return -ENOSYS;
  }

  return 0;
}

}  // namespace junction
