// the main header for Shenango's runtime

#pragma once

extern "C" {
#include <base/init.h>
#include <runtime/runtime.h>
}

#include <cstdlib>
#include <functional>
#include <string>

#include "junction/base/arch.h"

namespace junction::rt {

// The highest number of cores supported.
constexpr unsigned int kCoreLimit = NCPU;

// Initializes the runtime. If successful, calls @main_func and does not return.
int RuntimeInit(const std::string &cfg_path, std::function<void()> main_func);

// Shuts down the runtime and exits with EXIT_FAILURE or EXIT_SUCCESS.
inline void RuntimeExit(int status) { init_shutdown(status); }

// Gets the queueing delay of runqueue (thread queue) + packet queue
inline uint64_t RuntimeQueueUS() { return runtime_queue_us(); }

// Gets an estimate of the instantanious load as measured by the IOKernel.
inline float RuntimeLoad() { return runtime_load(); }

// Gets the current number of active cores
inline unsigned int RuntimeActiveCores() { return runtime_active_cores(); }

// Gets the maximum number of cores the runtime could run on.
inline unsigned int RuntimeMaxCores() { return runtime_max_cores(); }

// Gets the guaranteed number of cores the runtime will at least get.
inline unsigned int RuntimeGuaranteedCores() {
  return runtime_guaranteed_cores();
}

// Use when calling into the runtime's copy of libc
// Will disable preemption and set the correct FS register
class RuntimeLibcGuard {
 public:
  RuntimeLibcGuard() {
    preempt_disable();
    _prev_fs_base = ReadFsBase();
    SetFsBase(perthread_read(runtime_fsbase));
  }

  ~RuntimeLibcGuard() {
    SetFsBase(_prev_fs_base);
    preempt_enable();
  }

 private:
  uint64_t _prev_fs_base;
};

};  // namespace junction::rt
