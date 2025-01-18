#include "junction/fs/advisory_lock.h"

#include "junction/kernel/proc.h"

namespace junction {

AdvisoryLockMap &AdvisoryLockMap::Get() {
  static AdvisoryLockMap adv_map;
  return adv_map;
}

AdvisoryLockContext &AdvisoryLockMap::GetCtx(Inode *ino) {
  rt::SpinGuard g(lock_);
  std::shared_ptr<AdvisoryLockContext> &ptr = ctxs_[ino];
  if (!ptr) ptr.reset(new AdvisoryLockContext);
  return *ptr.get();
}

void AdvisoryLockMap::NotifyInodeDestroy(Inode *ino) {
  rt::SpinGuard g(lock_);
  ctxs_.erase(ino);
}

void AdvisoryLockMap::NotifyProcDestroy(pid_t pid) {
  rt::SpinGuard g(lock_);
  for (auto &[ino, lock] : ctxs_) lock->DropLocksForPid(pid);
}

AdvisoryLock fromFlock(struct flock *fl, File *file) {
  AdvisoryLock al;
  switch (fl->l_whence) {
    case SEEK_SET:
      al.start = fl->l_start;
      break;
    case SEEK_CUR:
      al.start = fl->l_start + file->get_off_ref();
      break;
    case SEEK_END:
      al.start = fl->l_start + file->get_size();
      break;
    default:
      al.start = -1;
  }

  al.end =
      fl->l_len ? al.start + fl->l_len - 1 : std::numeric_limits<off_t>::max();
  al.type = fl->l_type;
  al.pid = myproc().get_pid();
  return al;
}

bool ValidateAdvisoryLock(AdvisoryLock &al, struct flock *fl, File *file) {
  return al.start >= 0 && al.end >= al.start;
}

bool AdvisoryLockContext::ClearRange(ssize_t start, ssize_t end, pid_t pid) {
  assert(lock_.IsHeld());
  bool done = false;
  std::vector<AdvisoryLock> new_locks;
  for (auto it = holders_.begin(); it != holders_.end();) {
    AdvisoryLock &cur = *it;
    if (cur.pid != pid || !cur.overlaps(start, end)) {
      it++;
      continue;
    }

    done = true;

    // Break off left fragment.
    if (start > cur.start) {
      AdvisoryLock &left = new_locks.emplace_back(cur);
      left.end = start - 1;
    }

    // Truncate on right, or remove entirely.
    if (end < cur.end) {
      cur.start = end + 1;
      it++;
    } else {
      it = holders_.erase(it);
    }
  }

  holders_.insert(holders_.end(), new_locks.begin(), new_locks.end());
  return done;
}

void AdvisoryLockContext::DoUnlocks(AdvisoryLock &fl) {
  rt::WaitQueue tmp;
  {
    rt::SpinGuard g(lock_);
    if (ClearRange(fl.start, fl.end, fl.pid)) tmp.Splice(waiters_);
  }
  tmp.WakeAll();
}

Status<void> AdvisoryLockContext::DoGet(struct flock *fl, File *file) {
  AdvisoryLock al = fromFlock(fl, file);
  if (!ValidateAdvisoryLock(al, fl, file)) return MakeError(EINVAL);

  assert(al.type != F_UNLCK);
  rt::SpinGuard g(lock_);

  std::optional<AdvisoryLock> conflict = GetConflict(al);
  if (!conflict) {
    fl->l_type = F_UNLCK;
    return {};
  }

  fl->l_type = conflict->type;
  fl->l_start = conflict->start;
  fl->l_whence = SEEK_SET;
  fl->l_len = conflict->end - conflict->start + 1;
  fl->l_pid = conflict->pid;
  return {};
}

Status<void> AdvisoryLockContext::DoSet(struct flock *fl, bool wait,
                                        File *file) {
  AdvisoryLock al = fromFlock(fl, file);
  if (!ValidateAdvisoryLock(al, fl, file)) return MakeError(EINVAL);

  if (al.type == kFlockUnlock) {
    DoUnlocks(al);
    return {};
  }

  rt::ThreadWaker w;
  rt::SpinGuard g(lock_);

  if (wait) {
    if (!rt::WaitInterruptible(lock_, w, [&] { return !AnyConflicts(al); }))
      return MakeError(EINTR);
  } else if (AnyConflicts(al)) {
    return MakeError(EAGAIN);
  }

  ClearRange(al.start, al.end, al.pid);
  holders_.emplace_back(al);
  return {};
}

void AdvisoryLockContext::DropLocksForPid(pid_t pid) {
  rt::WaitQueue tmp;
  {
    rt::SpinGuard g(lock_);
    if (std::erase_if(holders_,
                      [&](AdvisoryLock &al) { return al.pid == pid; }))
      tmp.Splice(waiters_);
  }
  tmp.WakeAll();
}

}  // namespace junction
