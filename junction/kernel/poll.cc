#include "junction/base/intrusive_list.h"
#include "junction/bindings/log.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {

constexpr unsigned int kPollInval = POLLNVAL;

#if 0
class PollTrigger : public PollObserver {};

class EPollNotifier : boost::intrusive::list_base_hook<> {
 private:
  bool edge_triggered_;
  bool one_shot_;
  uint32_t events_;
  uint64_t user_data_;
};

class EPollFile : public File {
 private:
  rt::Spin lock_;
  rt::ThreadWaker waker_;
  boost::intrusive::list<EPollNotifier> triggered_events_;
  boost::intrusive::list<EPollNotifier> all_events_;
};
#endif

int DoPoll(struct pollfd *fds, nfds_t nfds,
           std::optional<uint64_t> timeout_us) {
  int nevents = 0;

  // Check each file; if at least one has events, no need to block.
  FileTable &ftbl = myproc().get_file_table();
  for (nfds_t i = 0; i < nfds; i++) {
    File *f = ftbl.Get(fds[i].fd);
    if (unlikely(!f)) {
      fds[i].revents = static_cast<short>(kPollInval);
      nevents++;
      continue;
    }

    PollSource &src = f->get_poll_source();
    short events = static_cast<short>(src.get_events());
    fds[i].revents = events & (fds[i].events | kPollErr | kPollHUp);
    if (fds[i].revents != 0) nevents++;
  }

  // Fast path: Return without blocking.
  if (nevents > 0 || (timeout_us && *timeout_us == 0)) return nevents;

  // Otherwise, init state to block on the FDs and timeout.
  rt::Spin lock;
  bool timed_out = false;
  rt::ThreadWaker th;

  // Setup a trigger for the timer (if needed).
  rt::Timer timeout_trigger([&lock, &th, &timed_out] {
    timed_out = true;
    rt::SpinGuard g(lock);
    th.Wake();
  });
  if (timeout_us) timeout_trigger.Start(*timeout_us);

  do {
    std::vector<Poller> triggers;
    triggers.reserve(nfds);

    // Setup a trigger for each file.
    for (nfds_t i = 0; i < nfds; i++) {
      File *f = ftbl.Get(fds[i].fd);
      assert(f != nullptr);
      triggers.emplace_back(
          [&lock, &th, &nevents, &entry = fds[i]](unsigned long ev) {
            int delta = entry.revents > 0 ? -1 : 0;
            short events = static_cast<short>(ev);
            entry.revents = events & (entry.events | kPollErr | kPollHUp);
            delta += entry.revents > 0 ? 1 : 0;
            if (delta != 0) {
              rt::SpinGuard g(lock);
              nevents += delta;
              if (nevents > 0) th.Wake();
            }
          });
      PollSource &src = f->get_poll_source();
      src.Attach(triggers.back());
    }

    // Block until an event has triggered.
    {
      rt::SpinGuard g(lock);
      g.Park(th, [&nevents, &timed_out] { return nevents > 0 || timed_out; });
    }

    // There's a tiny chance events will get cleared, causing zero @nevents.
  } while (nevents == 0 && !timed_out);

  if (timeout_us) timeout_trigger.Cancel();
  return nevents;
}

#if 0
int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, std::optional<uint64_t> timeout_us) {
  if (nfds > FD_SETSIZE) return -EINVAL;

  static constexpr short kSelectIn = (kPollIn | kPollHup | kPollErr);
  static constexpr short kSelectOut = (kPollOut | kPollErr);
  static constexpr short kSelectExcept = kPollPrio;

  struct select_data {
    int fd;
    short events;
    short revents;
    Poller p; 
  }

  std::vector<select_data> evtbl;
  int nevents;

  // Parse input event bit vectors.
  for (int i = 0; i < nfds; i++) {
    File *f = ftbl.Get(i);
    if (unlikely(!f)) return -EBADF;
    PollSource &src = f->get_poll_source();
    short pending_events = static_cast<short>(src.get_events());
    short events = 0;

    if (readfds && FD_ISSET(i, readfds)) {
      if ((pending_events & kSelectIn) != 0) {
        nevents++;
      } else {
        events |= kSelectIn;
        FD_CLR(i, readfds);
      }
    }
    if (writefds && FD_ISSET(i, writefds)) {
      if ((pending_events & kSelectOut) != 0) {
        nevents++;
      } else {
        events |= kSelectOut;
        FD_CLR(i, writefds);
      }
    }
    if (exceptfds && FD_ISSET(i, exceptfds)) {
      if ((pending_events & kSelectExcept) != 0) {
        nevents++;
      } else {
        events |= kSelectExcept;
        FD_CLR(i, exceptfds);
      }
    }

    if (!events || nevents > 0) continue;
    evtbl.emplace_back({.fd = i, .events = events, .revents = 0, .p = {}}); 
  }

  // Fast path: Return without blocking.
  if (nevents > 0 || (timeout_us && *timeout_us == 0)) return nevents;

  // Otherwise, init state to block on the FDs and timeout.
  rt::Spin lock;
  bool timed_out = false;
  rt::ThreadWaker th;

  // Setup a trigger for the timer (if needed).
  rt::Timer timeout_trigger([&lock, &th, &timed_out] {
    timed_out = true;
    rt::SpinGuard g(lock);
    th.Wake();
  });
  if (timeout_us) timeout_trigger.Start(*timeout_us);

  // Setup a trigger for each file.
  for (auto &ev : evtbl) {
      File *f = ftbl.Get(fds[i].fd);
      assert(f != nullptr);
      triggers.emplace_back(
          [&lock, &th, &nevents, &entry = fds[i]](unsigned long ev) {
            int delta = entry.revents > 0 ? -1 : 0;
            short events = static_cast<short>(ev);
            entry.revents = events & (entry.events | kPollErr | kPollHUp);
            delta += entry.revents > 0 ? 1 : 0;
            if (delta != 0) {
              rt::SpinGuard g(lock);
              nevents += delta;
              if (nevents > 0) th.Wake();
            }
          });
      PollSource &src = f->get_poll_source();
      src.Attach(triggers.back());
    }
}
#endif

}  // namespace

void PollSource::Notify() {
  rt::SpinGuard guard(lock_);
  for (auto &o : observers_) o.Notify(event_mask_);
}

int usys_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  if (timeout < 0) return DoPoll(fds, nfds, {});
  return DoPoll(fds, nfds, static_cast<uint64_t>(timeout) * rt::kMilliseconds);
}

int usys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *ts,
               const sigset_t *sigmask, size_t sigsetsize) {
  // TODO(amb): support signal masking
  if (!ts) return DoPoll(fds, nfds, {});
  uint64_t timeout_us = ts->tv_sec * rt::kSeconds + ts->tv_nsec / 1000;
  return DoPoll(fds, nfds, timeout_us);
}

#if 0
int usys_epoll_create1(int flags) {}

int usys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {}

int usys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                    int timeout) {}
#endif

}  // namespace junction
