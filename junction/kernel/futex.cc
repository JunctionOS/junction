// futex.cc - simple, low-performance futex implementation for FUTEX_WAIT and
// FUTEX_WAKE.

extern "C" {
#include <linux/futex.h>
}

#include <memory>
#include <unordered_map>

#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/kernel/usys.h"

namespace junction {

struct FutexKey {
  rt::Mutex mtx;
  rt::CondVar cv;
};

// Global table of futex keys, protected by a spin lock.
// Futex key entries are never deleted.
static std::unordered_map<uint32_t *, std::shared_ptr<FutexKey>> keys;
static rt::Spin futex_lock;

std::shared_ptr<FutexKey> getKey(uint32_t *key, bool create) {
  rt::SpinGuard lck(&futex_lock);

  auto it = keys.find(key);
  if (it == keys.end()) {
    if (!create) return nullptr;
    auto fk = std::make_shared<FutexKey>();
    keys[key] = fk;
    return fk;
  }

  return it->second;
}

int FutexBlock(uint32_t *key, uint32_t val) {
  auto fk = getKey(key, true);
  rt::MutexGuard g(&fk->mtx);
  if (ACCESS_ONCE(*key) != val) return -EAGAIN;
  fk->cv.Wait(&fk->mtx, [&] { return ACCESS_ONCE(*key) != val; });
  return 0;
}

int FutexWake(uint32_t *key) {
  auto fk = getKey(key, false);
  if (!fk) return 0;
  rt::MutexGuard g(&fk->mtx);
  fk->cv.SignalAll();
  return 0;
}

long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3) {
  if (futex_op & FUTEX_CLOCK_REALTIME) {
    static bool once;
    if (!once) {
      LOG(WARN) << "Futex timeout not supported";
      once = true;
    }
  }

  futex_op &= ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

  switch (futex_op) {
    case FUTEX_WAKE:
    case FUTEX_WAKE_BITSET:
      return FutexWake(uaddr);
    case FUTEX_WAIT:
    case FUTEX_WAIT_BITSET:
      return FutexBlock(uaddr, val);
    default:
      return -ENOSYS;
  }
}

}  // namespace junction
