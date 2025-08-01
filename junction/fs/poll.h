// poll.h - support for epoll(), poll(), select() etc.

#pragma once

extern "C" {
#include <poll.h>
#include <sys/epoll.h>
}

#include <functional>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/intrusive.h"
#include "junction/bindings/sync.h"
#include "junction/snapshot/cereal.h"

namespace junction {

// ensure event types can be used interchangably for epoll() and poll()
static_assert(EPOLLIN == POLLIN);
static_assert(EPOLLOUT == POLLOUT);
static_assert(EPOLLERR == POLLERR);
static_assert(EPOLLRDHUP == POLLRDHUP);
static_assert(EPOLLHUP == POLLHUP);
static_assert(EPOLLPRI == POLLPRI);

// event types
inline constexpr unsigned int kPollIn = EPOLLIN;        // available for read()
inline constexpr unsigned int kPollOut = EPOLLOUT;      // available for write()
inline constexpr unsigned int kPollErr = EPOLLERR;      // error condition
inline constexpr unsigned int kPollRDHUp = EPOLLRDHUP;  // reader closed
inline constexpr unsigned int kPollHUp = EPOLLHUP;      // writer closed
inline constexpr unsigned int kPollPrio = EPOLLPRI;  // priority event (TCP URG)

class PollSource;

namespace detail {
class EPollFile;
}  // namespace detail

// PollObserver provides a notification for each event from a PollSource.
class PollObserver {
 public:
  friend class PollSource;
  friend detail::EPollFile;

  PollObserver() noexcept = default;
  virtual ~PollObserver() { assert(!is_attached()); }

  PollObserver(const PollObserver &o) noexcept {}
  PollObserver &operator=(const PollObserver &o) {
    if (this != &o) src_ = nullptr;
    return *this;
  }
  PollObserver(PollObserver &&o) noexcept { assert(!is_attached()); }
  PollObserver &operator=(PollObserver &&o) noexcept {
    assert(!is_attached());
    src_ = nullptr;
    return *this;
  }

  [[nodiscard]] bool is_attached() const { return src_ != nullptr; }

  // Detach this observer from its PollSource.
  void Detach();

 private:
  // Notify informs the observer that the events have changed.
  virtual void Notify(unsigned int event_mask) = 0;

  IntrusiveListNode node_;
  PollSource *src_{nullptr};
};

void EpollObserverSave(cereal::BinaryOutputArchive &ar, const PollObserver &o);
void EpollObserverLoad(cereal::BinaryInputArchive &ar);

// PollSource generates events and delivers them to each PollObserver.
class alignas(kCacheLineSize) PollSource {
 public:
  friend detail::EPollFile;

  PollSource() noexcept = default;
  ~PollSource() {
    assert(observers_.empty());
    DetachEPollObservers();
  }

  // Gets the current mask of set events
  [[nodiscard]] unsigned int get_events() const {
    return read_once(event_mask_);
  }

  // Sets a mask of events and notifies (must be synchronized by caller).
  void Set(unsigned int event_mask);

  // Clears a mask of events and notifies (must be synchronized by caller).
  void Clear(unsigned int event_mask);

  // Registers an observer to receive events from this source.
  void Attach(PollObserver &o);

  // Unregisters an observer from this source.
  void Detach(PollObserver &o);

  // Sets the initial event mask (no notification sent).
  void Init(unsigned int event_mask) { event_mask_ = event_mask; }

  template <class Archive>
  void save(Archive &ar) const {
    // Save epoll observers.
    for (const PollObserver &o : epoll_observers_) {
      ar(true);
      EpollObserverSave(ar, o);
    }
    ar(false);
  }

  template <class Archive>
  void load(Archive &ar) {
    bool done;
    ar(done);

    while (done) {
      EpollObserverLoad(ar);
      ar(done);
    }
  }

 private:
  void Notify();
  void DetachEPollObservers();
  friend class PollSourceSet;

  rt::Spin lock_;
  unsigned int event_mask_{0};
  IntrusiveList<PollObserver, &PollObserver::node_> observers_;
  IntrusiveList<PollObserver, &PollObserver::node_> epoll_observers_;
};

class PollSourceSet {
 public:
  void Attach(PollSource *p) { sources_.push_back(p); }

  // May be called multiple times.
  void Detach(PollSource *p) { std::erase(sources_, p); }

  // Sets a mask of events and notifies (must be synchronized by caller).
  void Set(unsigned int event_mask) {
    for (auto &ps : sources_) ps->Set(event_mask);
  }

  // Clears a mask of events and notifies (must be synchronized by caller).
  void Clear(unsigned int event_mask) {
    for (auto &ps : sources_) ps->Clear(event_mask);
  }

  explicit operator bool() const { return sources_.size(); }

 private:
  std::vector<PollSource *> sources_;
};

class SinglePollSource {
 public:
  void Attach(PollSource *p) {
    assert(!source_);
    source_ = p;
  }

  // May be called multiple times.
  void Detach(PollSource *p) { source_ = nullptr; }

  // Sets a mask of events and notifies (must be synchronized by caller).
  void Set(unsigned int event_mask) { source_->Set(event_mask); }

  // Clears a mask of events and notifies (must be synchronized by caller).
  void Clear(unsigned int event_mask) { source_->Clear(event_mask); }

  explicit operator bool() const { return source_; }

 private:
  PollSource *source_{nullptr};
};

inline void PollSource::Set(unsigned int event_mask) {
  unsigned int cur = event_mask_;
  if ((cur & event_mask) == event_mask) return;
  event_mask_ = cur | event_mask;
  Notify();
}

inline void PollSource::Clear(unsigned int event_mask) {
  unsigned int cur = event_mask_;
  if ((cur & event_mask) == 0) return;
  event_mask_ = cur & ~event_mask;
  Notify();
}

inline void PollSource::Attach(PollObserver &o) {
  assert(o.src_ == nullptr);
  o.src_ = this;
  rt::SpinGuard g(lock_);
  observers_.push_back(o);
  unsigned int events = get_events();
  if (events != 0) o.Notify(events);
}

inline void PollSource::Detach(PollObserver &o) {
  assert(o.src_ != nullptr);
  o.src_ = nullptr;
  rt::SpinGuard g(lock_);
  observers_.erase(decltype(observers_)::s_iterator_to(o));
}

inline void PollObserver::Detach() { src_->Detach(*this); }

// Poller is a simple wrapper that runs a lambda when poll events trigger.
class Poller : public PollObserver {
 public:
  Poller() noexcept = default;
  explicit Poller(std::function<void(unsigned int)> func) noexcept
      : func_(std::move(func)) {}
  ~Poller() override = default;

  Poller(const Poller &p) noexcept = default;
  Poller &operator=(const Poller &p) {
    func_ = p.func_;
    return *this;
  }
  Poller(Poller &&p) noexcept
      : PollObserver(std::move(p)), func_(std::move(p.func_)) {}
  Poller &operator=(Poller &&p) noexcept {
    func_ = std::move(p.func_);
    return *this;
  }

 private:
  void Notify(unsigned int event_mask) override { func_(event_mask); }

  std::function<void(unsigned int)> func_;
};

}  // namespace junction
