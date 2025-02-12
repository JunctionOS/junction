// interval_set.h - provides a datastructure for managing a set of intervals

#pragma once

#include <map>

#include "junction/base/error.h"
#include "junction/snapshot/cereal.h"

namespace junction {

template <typename T>
concept IntervalData =
    std::movable<T> &&
    requires(T t, const T u, uintptr_t start, uintptr_t end) {
      { t.get_start() } -> std::convertible_to<uintptr_t>;
      { t.get_end() } -> std::convertible_to<uintptr_t>;
      { t.TrimTail(start) } -> std::same_as<void>;
      { t.TrimHead(end) } -> std::same_as<void>;
      { t.TryMergeRight(u) } -> std::convertible_to<bool>;
    };

template <IntervalData T>
class ExclusiveIntervalSet {
 public:
  std::map<uintptr_t, T>::iterator Clear(uintptr_t start, uintptr_t end) {
    auto it = intervals_.upper_bound(start);
    while (it != intervals_.end() && it->second.get_start() < end) {
      T &item = it->second;

      // [start, end) does not overlap on the left of [cur_start, cur_end).
      // Shorten item to [cur_start, start).
      if (start > item.get_start()) {
        T left = item;
        left.TrimTail(start);
        intervals_.insert(it, std::pair(start, std::move(left)));
      }

      // [start, end) either overlaps on the right or surrounds [item.start,
      // item.end). Either way item.end is being overwritten so remove it.
      assert(item.get_end() == it->first);
      if (end >= item.get_end()) {
        it = intervals_.erase(it);
        continue;
      }

      // [start, end) either overlaps on the left or is surrounded by
      // [item.start, item.end). Keep item.end and shorten it to [end,
      // item.end).
      item.TrimHead(end);
      it++;
    }

    return it;
  }

  void Insert(T &&item) {
    // overlapping mappings must be atomically cleared
    auto it = Clear(item.get_start(), item.get_end());

    // then insert the new mapping
    it = intervals_.insert(it, std::pair(item.get_end(), std::move(item)));

    // finally, try to merge with adjacent mappings
    if (it != intervals_.begin()) {
      auto prev_it = std::prev(it);
      TryMergeRight(prev_it, it->second);
    }

    if (auto next_it = std::next(it); next_it != intervals_.end()) {
      TryMergeRight(it, next_it->second);
    }
  }

  Status<std::reference_wrapper<T>> Find(uintptr_t start) {
    auto it = intervals_.upper_bound(start);
    if (it == intervals_.end() || it->second.get_start() > start)
      return MakeError(ENOENT);
    return it->second;
  }

  Status<std::reference_wrapper<T>> UpperBound(uintptr_t start) {
    auto it = intervals_.upper_bound(start);
    if (it == intervals_.end()) return MakeError(ENOENT);
    return it->second;
  }

  Status<uintptr_t> FindFreeRange(uintptr_t hint, size_t len,
                                  uintptr_t upper_lim, uintptr_t lower_lim) {
    // Try to accomodate a hint.
    if (hint != 0) {
      uintptr_t start = hint;
      uintptr_t end = hint + len;

      // Find the first region that ends after the start of the requested one.
      auto it = intervals_.upper_bound(start);
      // If no such region exists or the next region starts after the requested
      // end, the hinted address can be used.
      if (it == intervals_.end() || it->second.get_start() >= end) return start;

      // Try to place the request just before @it.
      auto prev = std::prev(it);
      uintptr_t new_start = it->second.get_start() - len;
      uintptr_t prev_end = prev == intervals_.begin() ? lower_lim : prev->first;
      if (new_start >= prev_end) return new_start;

      // Try to place the request just after @it.
      auto next = std::next(it);
      uintptr_t new_end = it->first + len;
      uintptr_t next_start =
          next == intervals_.end() ? upper_lim : next->second.get_start();
      if (new_end <= next_start) return it->second.get_end();
    }

    // Iterate from mm_end_ backwards looking for free slots.
    uintptr_t prev_start = upper_lim;
    auto it = intervals_.rbegin();
    while (it != intervals_.rend() && prev_start - it->first < len) {
      prev_start = it->second.get_start();
      it++;
    }

    uintptr_t addr = prev_start - len;
    if (addr < lower_lim) return MakeError(ENOMEM);
    return addr;
  }

  template <typename CheckFunc, typename ChangeFunc>
  void Modify(uintptr_t start, uintptr_t end, CheckFunc check,
              ChangeFunc change) {
    // We want the first interval [a,b] where b > start
    auto it = intervals_.upper_bound(start);
    auto prev_it = it == intervals_.begin() ? intervals_.end() : std::prev(it);
    while (it != intervals_.end() && it->second.get_start() < end) {
      auto f = finally([&prev_it, &it] { prev_it = it++; });
      T &item = it->second;

      // skip if the protection isn't changed
      if (!check(item)) {
        TryMergeRight(prev_it, item);
        continue;
      }

      // split the item to modify the right part? [start, item.end)
      if (start > item.get_start()) {
        T left = item;
        left.TrimTail(start);
        intervals_.insert(it, std::pair(start, std::move(left)));
        item.TrimHead(start);
      }

      // split the item to modify the left part? [item.start, end)
      if (end < item.get_end()) {
        T left = item;
        left.TrimTail(end);
        change(left);
        TryMergeRight(prev_it, left);
        intervals_.insert(it, std::pair(end, std::move(left)));
        item.TrimHead(end);
        continue;
      }

      change(item);
      TryMergeRight(prev_it, item);
    }

    // Try merging the next VMA after our stopping point.
    if (it != intervals_.end()) TryMergeRight(prev_it, it->second);
  }

  void clear() { intervals_.clear(); }

  [[nodiscard]] size_t size() const { return intervals_.size(); }

  auto begin() const { return intervals_.begin(); }
  auto end() const { return intervals_.end(); }

  auto begin() { return intervals_.begin(); }
  auto end() { return intervals_.end(); }

  template <typename Archive>
  void serialize(Archive &ar) {
    ar(intervals_);
  }

 private:
  bool TryMergeRight(std::map<uintptr_t, T>::iterator prev, T &rhs) {
    if (prev == intervals_.end()) return false;
    const T &lhs = prev->second;
    if (rhs.TryMergeRight(lhs)) {
      intervals_.erase(prev);
      return true;
    }

    return false;
  }

  std::map<uintptr_t, T> intervals_;
};

}  // namespace junction