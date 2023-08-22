// futex.h - support for futex synchronization

#pragma once

#include <climits>
#include <functional>
#include <optional>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/intrusive_list.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/proc.h"

namespace junction {

namespace detail {

struct futex_waiter {
  futex_waiter(Thread *th, uint32_t *key, uint32_t bitset)
      : th(th), key(key), bitset(bitset) {}

  Thread *th;
  uint32_t *key;
  uint32_t bitset;
  IntrusiveListNode node;
};

struct alignas(kCacheLineSize) futex_bucket {
  IntrusiveList<futex_waiter, &futex_waiter::node> futexes;
  rt::Spin lock;
};

}  // namespace detail

inline constexpr uint32_t kFutexBitsetAny = 0xFFFFFFFF;

class alignas(kCacheLineSize) FutexTable {
 public:
  FutexTable() = default;
  ~FutexTable() = default;

  FutexTable(FutexTable &&) = delete;
  FutexTable &operator=(FutexTable &&) = delete;
  FutexTable(const FutexTable &) = delete;
  FutexTable &operator=(const FutexTable &) = delete;

  // Wait blocks on the address @key. However, it returns ETIMEDOUT if the
  // timeout expires, or EAGAIN if @val doesn't match the value in the address.
  Status<void> Wait(uint32_t *key, uint32_t val,
                    uint32_t bitset = kFutexBitsetAny,
                    std::optional<Duration> timeout = {});

  // Wake unblocks up to @n threads waiting on the address @key. Returns the
  // number of threads woken.
  int Wake(uint32_t *key, int n = INT_MAX, uint32_t bitset = kFutexBitsetAny);

  // Scans the entire FutexTable for waiters owned by @p and wakes them.
  void CleanupProcess(Process *p);

  static FutexTable &GetFutexTable();

 private:
  static constexpr size_t kBuckets = 16;  // TODO(amb): allocate dynamically?

  // gets the right hash bucket for a key.
  detail::futex_bucket &get_bucket(uint32_t *key) {
    return buckets_[std::hash<uint32_t *>{}(key) % kBuckets];
  }

  detail::futex_bucket buckets_[kBuckets];
};

}  // namespace junction
