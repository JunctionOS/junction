#pragma once

#include <boost/program_options.hpp>

#include "junction/base/error.h"
#include "junction/kernel/proc.h"

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

class JunctionCfg {
 public:
  using program_options = boost::program_options::options_description;

  [[nodiscard]] const std::string_view get_chroot_path() const {
    return chroot_path;
  }

  [[nodiscard]] const std::string_view get_fs_config_path() const {
    return fs_config_path;
  }

  [[nodiscard]] const std::string_view get_interp_path() const {
    return interp_path;
  }

  [[nodiscard]] const std::string_view get_ld_path() const { return ld_path; }

  [[nodiscard]] const std::string_view get_preload_path() const {
    return preload_path;
  }

  [[nodiscard]] const std::vector<std::string> &get_binary_envp() const {
    return binary_envp;
  }

  [[nodiscard]] bool strace_enabled() const { return strace; }

  [[nodiscard]] program_options GetOptions();
  Status<void> FillFromArgs(int argc, char *argv[]);
  void Print();

  static JunctionCfg &get() { return singleton_; };

 private:
  std::string chroot_path{"/"};
  std::string fs_config_path;
  std::string interp_path{CUSTOM_GLIBC_INTERPRETER_PATH};
  std::string ld_path{CUSTOM_GLIBC_DIR};
  std::string preload_path{CUSTOM_GLIBC_PRELOAD};
  std::vector<std::string> binary_envp;
  bool strace{false};
  static JunctionCfg singleton_;
};

inline JunctionCfg &GetCfg() { return JunctionCfg::get(); }

std::string_view GetCwd();

Status<void> init();
Status<std::unique_ptr<Process>> InitTestProc();
void EnableMemoryAllocation();

}  // namespace junction
