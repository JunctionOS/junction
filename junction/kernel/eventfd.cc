// eventfd.cc - support for eventfds

extern "C" {
#include <sys/eventfd.h>
}

#include "junction/bindings/rcu.h"
#include "junction/bindings/wait.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {

static_assert(EFD_CLOEXEC == kFlagCloseExec);
static_assert(EFD_NONBLOCK == kFlagNonblock);

constexpr unsigned int kEventFdSemaphore = EFD_SEMAPHORE;
constexpr unsigned int kEventFdSupportedFlags =
    (kFlagNonblock | kEventFdSemaphore);

constexpr size_t kEventFdValSize = 8;

class EventFDFile : public File, public rt::RCUObject {
 public:
  EventFDFile(unsigned int initval, int flags) noexcept
      : File(FileType::kNormal, flags & kEventFdSupportedFlags,
             kModeReadWrite) {
    val_ = initval;
    get_poll_source().Set(kPollOut);
  }

  ~EventFDFile() = default;
  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override;
  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override;

 private:
  bool is_semaphore() const { return get_flags() & kEventFdSemaphore; }

  rt::Spin lock_;
  rt::WaitQueue queue_;
  uint64_t val_;
  static_assert(sizeof(val_) == kEventFdValSize);
};

Status<size_t> EventFDFile::Read(std::span<std::byte> buf,
                                 [[maybe_unused]] off_t *off) {
  if (buf.size_bytes() < kEventFdValSize) return MakeError(EINVAL);

  uint64_t *out = reinterpret_cast<uint64_t *>(buf.data());

  WakeOnSignal signaled(lock_);
  rt::SpinGuard guard(lock_);
  if (!val_) {
    if (is_nonblocking()) return MakeError(EAGAIN);
    guard.Park(queue_, [this, &signaled] { return val_ != 0 || signaled; });
  }
  if (signaled) return MakeError(EINTR);

  if (is_semaphore()) {
    *out = 1;
    val_--;
  } else {
    *out = val_;
    val_ = 0;
  }

  if (val_ == 0) get_poll_source().Clear(kPollIn);
  if (val_ < UINT64_MAX) get_poll_source().Set(kPollOut);
  queue_.WakeAll();
  return kEventFdValSize;
}

Status<size_t> EventFDFile::Write(std::span<const std::byte> buf,
                                  [[maybe_unused]] off_t *off) {
  if (buf.size_bytes() < kEventFdValSize) return MakeError(EINVAL);
  uint64_t val = *reinterpret_cast<const uint64_t *>(buf.data());
  if (val == UINT64_MAX) return MakeError(EINVAL);
  if (!val) return kEventFdValSize;

  WakeOnSignal signaled(lock_);
  rt::SpinGuard guard(lock_);

  // check for overflow
  if (val + val_ < val) {
    if (is_nonblocking()) return MakeError(EAGAIN);
    guard.Park(queue_, [this, &signaled, val] {
      return val + val_ >= val || signaled;
    });
  }
  if (signaled) return MakeError(EINTR);

  val_ += val;
  get_poll_source().Set(kPollIn);
  if (val_ == UINT64_MAX) get_poll_source().Clear(kPollOut);
  queue_.WakeAll();
  return kEventFdValSize;
}

}  // namespace

long usys_eventfd2(unsigned int initval, int flags) {
  std::shared_ptr<EventFDFile> efd(new EventFDFile(initval, flags),
                                   rt::RCUDeleter<EventFDFile>());
  return myproc().get_file_table().Insert(std::move(efd),
                                          (flags & kFlagCloseExec) > 0);
}

long usys_eventfd(unsigned int initval) {
  std::shared_ptr<EventFDFile> efd(new EventFDFile(initval, 0),
                                   rt::RCUDeleter<EventFDFile>());
  return myproc().get_file_table().Insert(std::move(efd));
}

}  // namespace junction
