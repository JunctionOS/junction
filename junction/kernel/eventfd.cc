// eventfd.cc - support for eventfds

extern "C" {
#include <sys/eventfd.h>
}

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

class EventFdFile : public File {
 public:
  EventFdFile(unsigned int initval, int flags) noexcept
      : File(FileType::kNormal, flags & kEventFdSupportedFlags,
             kModeReadWrite) {
    val_ = initval;
    get_poll_source().Set(kPollOut);
  }

  ~EventFdFile() = default;
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

Status<size_t> EventFdFile::Read(std::span<std::byte> buf,
                                 [[maybe_unused]] off_t *off) {
  if (buf.size_bytes() < kEventFdValSize) return MakeError(EINVAL);

  uint64_t *out = reinterpret_cast<uint64_t *>(buf.data());

  rt::SpinGuard guard(lock_);
  if (!val_) {
    if (is_nonblocking()) return MakeError(EAGAIN);
    guard.Park(queue_, [this] { return val_ != 0; });
  }

  if (is_semaphore()) {
    *out = 1;
    val_--;
  } else {
    *out = val_;
    val_ = 0;
  }

  if (val_ == 0) get_poll_source().Clear(kPollIn);
  queue_.WakeAll();
  return kEventFdValSize;
}

Status<size_t> EventFdFile::Write(std::span<const std::byte> buf,
                                  [[maybe_unused]] off_t *off) {
  if (buf.size_bytes() < kEventFdValSize) return MakeError(EINVAL);
  uint64_t val = *reinterpret_cast<const uint64_t *>(buf.data());
  if (val == UINT64_MAX) return MakeError(EINVAL);
  if (!val) return kEventFdValSize;

  rt::SpinGuard guard(lock_);

  // check for overflow
  if (val + val_ < val) {
    if (is_nonblocking()) return MakeError(EAGAIN);
    guard.Park(queue_, [this, val] { return val + val_ >= val; });
  }

  val_ += val;
  get_poll_source().Set(kPollIn);
  queue_.WakeAll();
  return kEventFdValSize;
}

}  // namespace

long usys_eventfd2(unsigned int initval, int flags) {
  auto efd = std::make_shared<EventFdFile>(initval, flags);
  return myproc().get_file_table().Insert(std::move(efd),
                                          (flags & kFlagCloseExec) > 0);
}

long usys_eventfd(unsigned int initval) {
  auto efd = std::make_shared<EventFdFile>(initval, 0);
  return myproc().get_file_table().Insert(std::move(efd));
}

}  // namespace junction
