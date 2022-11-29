// futex.cc - simple incomplete futex implementation for FUTEX_WAIT and
// FUTEX_WAKE.

extern "C" {
#include <linux/futex.h>
}

#include <boost/intrusive/list.hpp>
#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/kernel/usys.h"

namespace junction {

constexpr size_t kNumBuckets = 1024;
constexpr uint32_t kFutexBitsetAny = -1;

using namespace boost::intrusive;

struct FutexWaiter : list_base_hook<> {
  rt::ThreadWaker w;
  uint32_t *key;
  uint32_t bitset;
};

typedef list<FutexWaiter> FutexList;

FutexList waiter_list[kNumBuckets];
rt::Spin bucket_locks[kNumBuckets];

inline size_t GetBucket(uint32_t *ptr) {
  return (reinterpret_cast<uintptr_t>(ptr) >> 2) % kNumBuckets;
}

int FutexWait(uint32_t *key, uint32_t val, uint32_t bitset) {
  if (rt::read_once(*key) != val) return -EAGAIN;

  FutexWaiter fw;
  fw.key = key;
  fw.bitset = bitset;

  size_t bucket = GetBucket(key);
  rt::Spin &lck = bucket_locks[bucket];

  lck.Lock();

  // check with lock held to avoid missed wakeups
  if (rt::read_once(*key) != val) {
    lck.Unlock();
    return 0;
  }

  // append ourselves to the waitlist
  waiter_list[bucket].push_back(fw);

  // wait to be woken
  fw.w.Arm();
  lck.UnlockAndPark();

  return 0;
}

int FutexWake(uint32_t *key, int n, uint32_t bitset) {
  size_t bucket = GetBucket(key);
  rt::SpinGuard lck(&bucket_locks[bucket]);
  FutexList &l = waiter_list[bucket];

  auto it = l.begin();
  int i = 0;

  while (i < n && it != l.end()) {
    if (it->key != key || !(it->bitset & bitset)) {
      it++;
      continue;
    }

    // We can't wake the thread until we have removed the waiter from the list,
    // since the waiter is stored on the sleeping thread's stack. move the
    // threadwaker so we can safely remove the waiter from the list and then
    // wake up the thread.
    rt::ThreadWaker w = std::move(it->w);
    it = l.erase(it);
    w.Wake();
    i++;
  }

  return i;
}

long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3) {
  if (timeout) {
    static bool once;
    if (!once) {
      LOG(WARN) << "Futex timeout not supported";
      once = true;
    }
  }

  futex_op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

  switch (futex_op) {
    case FUTEX_WAKE:
      val3 = kFutexBitsetAny;
    case FUTEX_WAKE_BITSET:
      return FutexWake(uaddr, val, val3);
    case FUTEX_WAIT:
      val3 = kFutexBitsetAny;
    case FUTEX_WAIT_BITSET:
      return FutexWait(uaddr, val, val3);
    default:
      return -ENOSYS;
  }
}

}  // namespace junction
