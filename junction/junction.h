#pragma once

#include <memory>
#include <optional>
#include <vector>

#include "junction/base/error.h"
#include "junction/bindings/net.h"

#ifndef CUSTOM_GLIBC_INTERPRETER_PATH
#define CUSTOM_GLIBC_INTERPRETER_PATH
#endif

#ifndef CUSTOM_GLIBC_DIR
#define CUSTOM_GLIBC_DIR
#endif

#ifndef CUSTOM_GLIBC_PRELOAD
#define CUSTOM_GLIBC_PRELOAD
#endif

namespace junction {

class Process;

class alignas(kCacheLineSize) JunctionCfg {
 public:
  [[nodiscard]] std::string_view get_chroot_path() const { return chroot_path; }

  [[nodiscard]] std::string_view get_fs_config_path() const {
    return fs_config_path;
  }

  [[nodiscard]] std::string_view get_interp_path() const { return interp_path; }

  [[nodiscard]] std::string_view get_ld_path() const { return ld_path; }

  [[nodiscard]] const std::string &get_glibc_path() const { return glibc_path; }

  [[nodiscard]] const std::string &get_preload_path() const {
    return preload_path;
  }

  [[nodiscard]] const std::vector<std::string> &get_binary_envp() const {
    return binary_envp;
  }

  [[nodiscard]] bool strace_enabled() const { return strace; }
  [[nodiscard]] bool restoring() const { return restore; }
  [[nodiscard]] bool kernel_restoring() const { return kernel_restoring_; }
  [[nodiscard]] bool expecting_snapshot() const { return expecting_snapshot_; }
  [[nodiscard]] bool jif() const { return jif_; }
  [[nodiscard]] bool stack_switch_enabled() const { return stack_switching; }
  [[nodiscard]] bool madv_dontneed_remap() const { return madv_remap; }
  [[nodiscard]] bool cache_linux_fs() const { return cache_linux_fs_; }
  [[nodiscard]] bool restore_populate() const { return restore_populate_; }
  [[nodiscard]] int snapshot_on_stop() const { return snapshot_on_stop_; }
  [[nodiscard]] bool mem_trace() const { return mem_trace_; }
  [[nodiscard]] bool snapshot_terminate() const {
    return terminate_after_snapshot_;
  }
  [[nodiscard]] uint16_t port() const { return port_; }
  [[nodiscard]] const std::string &get_snapshot_prefix() const {
    return snapshot_prefix_;
  }

  [[nodiscard]] const std::string &get_function_name() const {
    return function_name_;
  }

  [[nodiscard]] netaddr get_dispatch_netaddr() const {
    netaddr addr;
    str_to_netaddr(func_dispatch_addr.c_str(), &addr);
    return addr;
  }

  [[nodiscard]] const std::string &get_dispatch_ip_str() const {
    return func_dispatch_addr;
  }

  static void PrintOptions();
  Status<void> FillFromArgs(int argc, char *argv[]);
  void Print();

  static JunctionCfg &get() { return singleton_; };
  std::string GetArg(const std::string &arg);
  bool GetBool(const std::string &name);

 private:
  // Hot state
  bool strace;
  bool madv_remap;
  bool expecting_snapshot_;
  bool restore_populate_;

  // Cold state
  std::string chroot_path;
  std::string fs_config_path;
  std::string interp_path;
  std::string glibc_path;
  std::string ld_path;
  std::string preload_path;
  std::vector<std::string> binary_envp;

  uint16_t port_;
  bool restore;
  bool kernel_restoring_;
  bool jif_;
  bool stack_switching;
  bool cache_linux_fs_;
  bool terminate_after_snapshot_;
  int snapshot_on_stop_;
  bool mem_trace_;
  std::string snapshot_prefix_;
  std::string func_dispatch_addr;
  std::string function_name_;
  static JunctionCfg singleton_;
};

inline JunctionCfg &GetCfg() { return JunctionCfg::get(); }

std::string_view GetLinuxCwd();
pid_t GetLinuxPid();

Status<void> init();
Status<void> InitUnixTime();
Status<void> InitControlServer();
Status<void> InitChannelClient();
Status<std::unique_ptr<Process>> InitTestProc();
void MarkRuntimeReady();
[[nodiscard]] bool IsRuntimeReady();
}  // namespace junction
