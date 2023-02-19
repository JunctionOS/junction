// poll.cc - support for poll(), select(), and epoll()

// glibc uses a very expensive way to check bounds in FD sets, so disable it.
#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 0

#include <memory>

#include "junction/base/compiler.h"
#include "junction/base/intrusive_list.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/time.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {

constexpr unsigned int kPollInval = POLLNVAL;
constexpr unsigned int kEPollEdgeTriggered = EPOLLET;
constexpr unsigned int kEPollOneShot = EPOLLONESHOT;
constexpr unsigned int kEPollExclusive = EPOLLEXCLUSIVE;

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

  // Pack args to avoid heap allocations.
  struct {
    rt::Spin &lock;
    rt::ThreadWaker &th;
    int &nevents;
  } args = {lock, th, nevents};

  // Setup a trigger for each file.
  std::vector<Poller> triggers;
  triggers.reserve(nfds);
  for (nfds_t i = 0; i < nfds; i++) {
    triggers.emplace_back([&args, &entry = fds[i]](unsigned int pev) {
      int delta = entry.revents > 0 ? -1 : 0;
      short events = static_cast<short>(pev);
      entry.revents = events & (entry.events | kPollErr | kPollHUp);
      delta += entry.revents > 0 ? 1 : 0;
      if (delta != 0) {
        rt::SpinGuard g(args.lock);
        args.nevents += delta;
        if (args.nevents > 0) args.th.Wake();
      }
    });
    File *f = ftbl.Get(fds[i].fd);
    assert(f != nullptr);
    PollSource &src = f->get_poll_source();
    src.Attach(triggers.back());
  }

  while (true) {
    // Block until an event has triggered.
    {
      rt::SpinGuard g(lock);
      g.Park(th, [&nevents, &timed_out] { return nevents > 0 || timed_out; });
    }

    for (auto &p : triggers) p.Detach();

    // There's a tiny chance events will get cleared, causing zero @nevents.
    if (likely(nevents > 0 || timed_out)) break;

    for (nfds_t i = 0; i < nfds; i++) {
      File *f = ftbl.Get(fds[i].fd);
      assert(f != nullptr);
      PollSource &src = f->get_poll_source();
      src.Attach(triggers[i]);
    }
  }

  if (timeout_us) timeout_trigger.Cancel();
  return nevents;
}

struct select_fd {
  int fd;
  short events;
  short revents;
  Poller p;
};

constexpr short kSelectIn = (kPollIn | kPollHUp | kPollErr);
constexpr short kSelectOut = (kPollOut | kPollErr);
constexpr short kSelectExcept = kPollPrio;

std::vector<select_fd> DecodeSelectFDs(int nfds, fd_set *readfds,
                                       fd_set *writefds, fd_set *exceptfds) {
  std::vector<select_fd> sfds;
  sfds.reserve(nfds);

  for (int i = 0; i < nfds; i++) {
    short events = 0;

    if (readfds && FD_ISSET(i, readfds)) {
      events |= kSelectIn;
      FD_CLR(i, readfds);
    }
    if (writefds && FD_ISSET(i, writefds)) {
      events |= kSelectOut;
      FD_CLR(i, writefds);
    }
    if (exceptfds && FD_ISSET(i, exceptfds)) {
      events |= kSelectExcept;
      FD_CLR(i, exceptfds);
    }

    if (!events) continue;
    sfds.push_back(select_fd{.fd = i, .events = events, .revents = 0, .p = {}});
  }

  return sfds;
}

int EncodeSelectFDs(const std::vector<select_fd> &sfds, fd_set *readfds,
                    fd_set *writefds, fd_set *exceptfds) {
  int count = 0;

  for (const auto &sfd : sfds) {
    if ((sfd.events & kSelectIn) == kSelectIn &&
        (sfd.revents & kSelectIn) != 0) {
      FD_SET(sfd.fd, readfds);
      count++;
    }
    if ((sfd.events & kSelectOut) == kSelectOut &&
        (sfd.revents & kSelectOut) != 0) {
      FD_SET(sfd.fd, writefds);
      count++;
    }
    if ((sfd.events & kSelectExcept) == kSelectExcept &&
        (sfd.revents & kSelectExcept) != 0) {
      FD_SET(sfd.fd, exceptfds);
      count++;
    }
  }

  return count;
}

int DoSelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
             std::optional<uint64_t> timeout_us) {
  if (nfds > FD_SETSIZE) return -EINVAL;

  // Decode the events into a more convenient format.
  std::vector<select_fd> sfds =
      DecodeSelectFDs(nfds, readfds, writefds, exceptfds);

  // Check whether events are pending before blocking.
  FileTable &ftbl = myproc().get_file_table();
  int nevents = 0;
  for (auto &sfd : sfds) {
    File *f = ftbl.Get(sfd.fd);
    if (unlikely(!f)) return -EBADF;
    PollSource &src = f->get_poll_source();
    short pev = static_cast<short>(src.get_events());
    if ((pev & sfd.events) != 0) {
      sfd.revents = pev & sfd.events;
      nevents++;
    }
  }

  // Fast path: Return without blocking.
  if (nevents > 0) return EncodeSelectFDs(sfds, readfds, writefds, exceptfds);
  if (timeout_us && *timeout_us == 0) return 0;

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

  // Pack args to avoid heap allocations.
  struct {
    rt::Spin &lock;
    rt::ThreadWaker &th;
    int &nevents;
  } args = {lock, th, nevents};

  // Setup a trigger for each file.
  for (auto &sfd : sfds) {
    sfd.p = Poller([&args, &entry = sfd](unsigned int pev) {
      int delta = entry.revents > 0 ? -1 : 0;
      entry.revents = (static_cast<short>(pev) & entry.events);
      delta += entry.revents > 0 ? 1 : 0;
      if (delta != 0) {
        rt::SpinGuard g(args.lock);
        args.nevents += delta;
        if (args.nevents > 0) args.th.Wake();
      }
    });
    File *f = ftbl.Get(sfd.fd);
    assert(f != nullptr);
    PollSource &src = f->get_poll_source();
    src.Attach(sfd.p);
  }

  while (true) {
    // Block until an event has triggered.
    {
      rt::SpinGuard g(lock);
      g.Park(th, [&nevents, &timed_out] { return nevents > 0 || timed_out; });
    }

    for (auto &sfd : sfds) sfd.p.Detach();

    // There's a tiny chance events will get cleared, causing zero @nevents.
    if (likely(nevents > 0 || timed_out)) break;

    for (auto &sfd : sfds) {
      File *f = ftbl.Get(sfd.fd);
      assert(f != nullptr);
      PollSource &src = f->get_poll_source();
      src.Attach(sfd.p);
    }
  }

  if (timeout_us) timeout_trigger.Cancel();
  return EncodeSelectFDs(sfds, readfds, writefds, exceptfds);
}

}  // namespace

namespace detail {

class EPollObserver : public PollObserver {
 public:
  friend EPollFile;

  EPollObserver(EPollFile &epollf, File &f, int32_t watched_events,
                uint64_t user_data)
      : epollf_(&epollf),
        f_(&f),
        watched_events_(watched_events),
        user_data_(user_data) {}
  ~EPollObserver() = default;

  EPollObserver(const EPollObserver &o) noexcept = delete;
  EPollObserver &operator=(const EPollObserver &o) = delete;
  EPollObserver(EPollObserver &&o) noexcept = delete;
  EPollObserver &operator=(EPollObserver &&o) = delete;

 private:
  void Notify(unsigned int event_mask) override;

  bool attached_{false};  // TODO(amb): switch to better intrusive list?
  bool one_shot_triggered_{false};
  EPollFile *epollf_;
  File *f_;
  uint32_t watched_events_;
  uint32_t triggered_events_{0};
  uint64_t user_data_;
  IntrusiveListNode node_;
};

class EPollFile : public File {
 public:
  EPollFile() : File(FileType::kSpecial, 0, 0) {}
  ~EPollFile();

  static void Notify(PollSource &s);

  bool Add(File &f, uint32_t events, uint64_t user_data);
  bool Modify(File &f, uint32_t events, uint64_t user_data);
  bool Delete(File &f);
  int Wait(std::span<epoll_event> events, std::optional<uint64_t> timeout);

  void AddEvent(EPollObserver &o) {
    if (std::exchange(o.attached_, true)) return;
    rt::SpinGuard g(lock_);
    events_.push_back(o);
    waker_.Wake();
  }

  void RemoveEvent(EPollObserver &o) {
    if (!std::exchange(o.attached_, false)) return;
    rt::SpinGuard g(lock_);
    events_.erase(decltype(events_)::s_iterator_to(o));
  }

 private:
  rt::Spin lock_;
  rt::ThreadWaker waker_;
  IntrusiveList<EPollObserver, &EPollObserver::node_> events_;
};

EPollFile::~EPollFile() {
  FileTable &ftbl = myproc().get_file_table();
  ftbl.ForEach([this](File &f) { Delete(f); });
}

void EPollFile::Notify(PollSource &s) {
  bool exclusive = false;
  for (auto &o : s.epoll_observers_) {
    auto &oe = static_cast<EPollObserver &>(o);
    if ((oe.watched_events_ & kEPollOneShot) != 0) {
      if (std::exchange(oe.one_shot_triggered_, true)) continue;
    }
    if ((oe.watched_events_ & kEPollExclusive) != 0) {
      if (std::exchange(exclusive, true)) continue;
    }
    oe.Notify(s.get_events());
  }
}

bool EPollFile::Add(File &f, uint32_t events, uint64_t user_data) {
  events |= (kPollHUp | kPollErr);  // can't be ignored
  auto o = std::make_unique<EPollObserver>(*this, f, events, user_data);
  PollSource &src = f.get_poll_source();
  rt::SpinGuard guard(src.lock_);
  for (const auto &o : src.epoll_observers_)
    if (unlikely(static_cast<const EPollObserver &>(o).f_ == &f)) return false;
  src.epoll_observers_.push_back(*o);
  o->Notify(src.get_events());
  o.release();
  return true;
}

bool EPollFile::Modify(File &f, uint32_t events, uint64_t user_data) {
  events |= (kPollHUp | kPollErr);  // can't be ignored
  PollSource &src = f.get_poll_source();
  rt::SpinGuard guard(src.lock_);
  for (auto &o : src.epoll_observers_) {
    auto &oe = static_cast<EPollObserver &>(o);
    if (oe.epollf_ != this) continue;
    oe.watched_events_ = events;
    oe.user_data_ = user_data;
    oe.one_shot_triggered_ = false;
    oe.Notify(oe.triggered_events_);
    return true;
  }
  return false;
}

bool EPollFile::Delete(File &f) {
  PollSource &src = f.get_poll_source();
  rt::SpinGuard guard(src.lock_);
  auto it = src.epoll_observers_.begin();
  while (it != src.epoll_observers_.end()) {
    auto &oe = static_cast<EPollObserver &>(*it);
    if (oe.epollf_ == this) {
      RemoveEvent(oe);
      src.epoll_observers_.erase_and_dispose(it,
                                             [](PollObserver *o) { delete o; });
      return true;
    }
    ++it;
  }
  return false;
}

int EPollFile::Wait(std::span<epoll_event> events_out,
                    std::optional<uint64_t> timeout_us) {
  // Setup a timer for timeouts.
  bool timer_armed = false;
  bool timed_out = false;
  rt::Timer timer([this, &timed_out] {
    timed_out = true;
    rt::SpinGuard g(lock_);
    waker_.Wake();
  });

  // Block until an event has triggered.
  auto it = events_out.begin();
  {
    rt::SpinGuard g(lock_);

    // Arm the timer if needed.
    if (events_.empty() && timeout_us) {
      if (*timeout_us == 0) return 0;
      lock_.Unlock();
      timer.Start(*timeout_us);
      timer_armed = true;
      lock_.Lock();
    }

    // Wait for events to be ready.
    g.Park(waker_,
           [this, &timed_out] { return !events_.empty() || timed_out; });

    // Generate an array of events to report to the caller.
    IntrusiveList<EPollObserver, &EPollObserver::node_> tmp;
    while (!events_.empty() && it != events_out.end()) {
      EPollObserver &o = events_.front();
      it->events = o.triggered_events_ & o.watched_events_;
      it->data.u64 = o.user_data_;
      ++it;
      events_.pop_front();
      if ((o.watched_events_ & kEPollEdgeTriggered) != 0) {
        o.attached_ = false;
        continue;
      }
      tmp.push_back(o);
    }

    // Put the events that were delivered at the end for better fairness.
    events_.splice(events_.end(), tmp);
  }

  if (timer_armed) timer.Cancel();
  return std::distance(events_out.begin(), it);
}

void EPollObserver::Notify(uint32_t events) {
  triggered_events_ = events;
  if ((triggered_events_ & watched_events_) != 0)
    epollf_->AddEvent(*this);
  else
    epollf_->RemoveEvent(*this);
}

}  // namespace detail

namespace {

// Creates a new EPoll file.
int CreateEPollFile() {
  auto f = std::make_shared<detail::EPollFile>();
  return myproc().get_file_table().Insert(std::move(f));
}

int DoEPollWait(int epfd, struct epoll_event *events, int maxevents,
                std::optional<uint64_t> timeout_us) {
  if (unlikely(maxevents < 0)) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(epfd);
  if (unlikely(!f)) return -EBADF;
  auto *epf = most_derived_cast<detail::EPollFile>(f);
  if (unlikely(!epf)) return -EINVAL;
  return epf->Wait({events, static_cast<size_t>(maxevents)}, timeout_us);
}

}  // namespace

void PollSource::Notify() {
  rt::SpinGuard guard(lock_);
  for (auto &o : observers_) o.Notify(event_mask_);
  detail::EPollFile::Notify(*this);
}

int usys_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  if (timeout < 0) return DoPoll(fds, nfds, {});
  return DoPoll(fds, nfds, static_cast<uint64_t>(timeout) * rt::kMilliseconds);
}

int usys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *ts,
               const sigset_t *sigmask, size_t sigsetsize) {
  // TODO(amb): support signal masking
  if (!ts) return DoPoll(fds, nfds, {});
  return DoPoll(fds, nfds, timespec_to_us(*ts));
}

int usys_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                struct timeval *tv) {
  // TODO(amb): On linux, @tv is modified to reflect the time left.
  if (!tv) return DoSelect(nfds, readfds, writefds, exceptfds, {});
  return DoSelect(nfds, readfds, writefds, exceptfds, timeval_to_us(*tv));
}

int usys_pselect6(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, const struct timespec *ts) {
  // TODO(amb): support signal masking
  if (!ts) return DoSelect(nfds, readfds, writefds, exceptfds, {});
  return DoSelect(nfds, readfds, writefds, exceptfds, timespec_to_us(*ts));
}

// This variant is deprecated, and size is ignored.
int usys_epoll_create(int size) { return CreateEPollFile(); }

// TODO(amb): support FD_CLOEXEC flag
int usys_epoll_create1(int flags) { return CreateEPollFile(); }

int usys_epoll_ctl(int epfd, int op, int fd, const epoll_event *event) {
  // get the epoll file
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(epfd);
  if (unlikely(!f)) return -EBADF;
  auto *epf = most_derived_cast<detail::EPollFile>(f);
  if (unlikely(!epf)) return -EINVAL;

  // get the monitored file
  f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;

  // handle the operation
  switch (op) {
    case EPOLL_CTL_ADD:
      if (!epf->Add(*f, event->events, event->data.u64)) return -EEXIST;
      break;
    case EPOLL_CTL_MOD:
      if (!epf->Modify(*f, event->events, event->data.u64)) return -ENOENT;
      break;
    case EPOLL_CTL_DEL:
      if (!epf->Delete(*f)) return -ENOENT;
      break;
    default:
      return -EINVAL;
  }

  return 0;
}

int usys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                    int timeout) {
  std::optional<uint64_t> timeout_us{};
  if (timeout >= 0)
    timeout_us = static_cast<uint64_t>(timeout * rt::kMilliseconds);
  return DoEPollWait(epfd, events, maxevents, timeout_us);
}

int usys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout, const sigset_t *sigmask) {
  // TODO(amb): support signal masking
  std::optional<uint64_t> timeout_us{};
  if (timeout >= 0)
    timeout_us = static_cast<uint64_t>(timeout * rt::kMilliseconds);
  return DoEPollWait(epfd, events, maxevents, timeout_us);
}

int usys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                      const struct timespec *timeout, const sigset_t *sigmask) {
  // TODO(amb): support signal masking
  std::optional<uint64_t> timeout_us{};
  if (timeout) timeout_us = timespec_to_us(*timeout);
  return DoEPollWait(epfd, events, maxevents, timeout_us);
}

}  // namespace junction
