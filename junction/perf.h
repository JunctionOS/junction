#pragma once

#include <linux/perf_event.h>

#include "junction/kernel/ksys.h"

namespace junction {

static inline int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                                  int cpu, int group_fd, unsigned long flags) {
  return ksyscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// Hacky class to monitor perf events using low-overhead RDPMC instructions with
// the assistance of the Linux kernel. May be buggy, use with caution.
class PerfEventMon {
 public:
  [[nodiscard]] PerfEventMon(uint32_t type, uint64_t config) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));

    pe.type = type;
    pe.config = config;
    pe.size = sizeof(struct perf_event_attr);
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    fd_ = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd_ == -1) throw std::runtime_error("failed to open perf event");

    mpage_ = reinterpret_cast<struct perf_event_mmap_page *>(
        ksys_mmap(NULL, kPageSize, PROT_READ, MAP_SHARED, fd_, 0));
    if (mpage_ == MAP_FAILED) {
      ksys_close(fd_);
      throw std::runtime_error("failed to mmap perf event page");
    }

    if (!mpage_->cap_user_rdpmc) {
      ksys_munmap(mpage_, kPageSize);
      ksys_close(fd_);
      throw std::runtime_error("rdpmc not available");
    }

    Reset();
    Enable();
  }

  void Reset() {
    if (unlikely(syscall_ioctl(fd_, PERF_EVENT_IOC_RESET, 0)))
      throw std::runtime_error("perf event reset failed");
  }

  void Disable() {
    if (unlikely(syscall_ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0)))
      throw std::runtime_error("perf event disable failed");
  }

  void Enable() {
    if (unlikely(syscall_ioctl(fd_, PERF_EVENT_IOC_ENABLE, 0)))
      throw std::runtime_error("perf event enable failed");
  }

  [[nodiscard]] uint64_t Sample() {
    uint32_t seq, idx, width;
    uint64_t pmcval, count;

    do {
      seq = mpage_->lock;
      barrier();

      idx = mpage_->index;
      count = mpage_->offset;

      if (mpage_->cap_user_rdpmc && idx) {
        width = mpage_->pmc_width;
        pmcval = __builtin_ia32_rdpmc(idx - 1);
        pmcval <<= 64 - width;
        pmcval >>= 64 - width;
        count += pmcval;
      }

      barrier();
    } while (mpage_->lock != seq);
    return count;
  }

  // disable copy.
  PerfEventMon(const PerfEventMon &) = delete;
  PerfEventMon &operator=(const PerfEventMon &) = delete;

  // allow move.
  PerfEventMon(PerfEventMon &&f) noexcept
      : fd_(std::exchange(f.fd_, -1)),
        mpage_(std::exchange(f.mpage_, nullptr)) {}
  PerfEventMon &operator=(PerfEventMon &&f) noexcept {
    fd_ = std::exchange(f.fd_, -1);
    mpage_ = std::exchange(f.mpage_, nullptr);
    return *this;
  }

  ~PerfEventMon() {
    ksys_munmap(mpage_, kPageSize);
    ksys_close(fd_);
  }

 private:
  int fd_{-1};
  struct perf_event_mmap_page *mpage_{nullptr};
};

static inline PerfEventMon L1DMonitor(bool reads, bool misses_only) {
  uint64_t config = PERF_COUNT_HW_CACHE_L1D;
  if (reads)
    config |= (PERF_COUNT_HW_CACHE_OP_READ << 8);
  else
    config |= (PERF_COUNT_HW_CACHE_OP_WRITE << 8);
  if (misses_only)
    config |= (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
  else
    config |= (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);

  return PerfEventMon(PERF_TYPE_HW_CACHE, config);
}

static inline PerfEventMon LLMonitor(bool reads, bool misses_only) {
  uint64_t config = PERF_COUNT_HW_CACHE_LL;
  if (reads)
    config |= (PERF_COUNT_HW_CACHE_OP_READ << 8);
  else
    config |= (PERF_COUNT_HW_CACHE_OP_WRITE << 8);
  if (misses_only)
    config |= (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
  else
    config |= (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);

  return PerfEventMon(PERF_TYPE_HW_CACHE, config);
}

static inline PerfEventMon TLBMonitor(bool data, bool misses_only) {
  uint64_t config = data ? PERF_COUNT_HW_CACHE_DTLB : PERF_COUNT_HW_CACHE_ITLB;
  config |= (PERF_COUNT_HW_CACHE_OP_READ << 8);
  if (misses_only)
    config |= (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
  else
    config |= (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);
  return PerfEventMon(PERF_TYPE_HW_CACHE, config);
}

static inline PerfEventMon L2MissMonitor() {
  // L2_RQSTS.MISS on Sapphire Rapids.
  return PerfEventMon(PERF_TYPE_RAW, 0x3F24);
}

}  // namespace junction