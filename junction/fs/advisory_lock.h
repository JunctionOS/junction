// advisory_lock.h - Implements POSIX record locks.

#pragma once

extern "C" {
#include <fcntl.h>
}

#include <optional>
#include <vector>

#include "junction/bindings/sync.h"
#include "junction/snapshot/cereal.h"

namespace junction {

// Read flock.
inline constexpr short kFlockRead = F_RDLCK;
// Write flock.
inline constexpr short kFlockWrite = F_WRLCK;
// Unlock flock.
inline constexpr short kFlockUnlock = F_UNLCK;

class File;
class Inode;
class AdvisoryLockContext;

// Caller must have hold reference for ino.
AdvisoryLockContext &GetAdvLockContext(Inode *ino);
void AdvLockNotifyInodeDestroy(Inode *ino);
void AdvLockNotifyProcDestroy(pid_t pid);

struct AdvisoryLock {
  short type;
  ssize_t start;
  ssize_t end;  // inclusive
  pid_t pid;

  [[nodiscard]] bool overlaps(const AdvisoryLock &o) {
    return o.start <= end && o.end >= start;
  }

  [[nodiscard]] bool overlaps(ssize_t o_start, ssize_t o_end) {
    return o_start <= end && o_end >= start;
  }

  [[nodiscard]] bool conflicts(const AdvisoryLock &o) {
    if (!overlaps(o)) return false;
    if (o.pid == pid) return false;
    return o.type != kFlockRead || type != kFlockRead;
  }

  template <typename Archive>
  void serialize(Archive &ar) {
    ar(type, start, end, pid);
  }
};

// Low performance implementation of POSIX record locks.
class AdvisoryLockContext {
 public:
  Status<void> DoSet(struct flock *fl, bool wait, File *f);
  Status<void> DoGet(struct flock *fl, File *f);
  void DropLocksForPid(pid_t pid);

 private:
  [[nodiscard]] bool AnyConflicts(AdvisoryLock &al) {
    for (auto &lck : holders_)
      if (lck.conflicts(al)) return true;
    return false;
  }

  std::optional<AdvisoryLock> GetConflict(AdvisoryLock &al) {
    for (auto &lck : holders_)
      if (lck.conflicts(al)) return lck;
    return std::nullopt;
  }

  void DoUnlocks(AdvisoryLock &fl);
  bool ClearRange(ssize_t start, ssize_t end, pid_t pid);

  template <typename Archive>
  void serialize(Archive &ar) {
    ar(holders_);
  }

  rt::Spin lock_;
  rt::WaitQueue waiters_;
  std::vector<AdvisoryLock> holders_;
};

}  // namespace junction