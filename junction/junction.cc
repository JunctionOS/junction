
#include <boost/program_options.hpp>
// Include base/assert.h now to ensure correct definition of assert is used.
extern "C" {
#include <base/assert.h>
}

#include <fstream>
#include <iostream>
#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/fs/fs.h"
#include "junction/junction.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/signal.h"
#include "junction/shim/backend/init.h"
#include "junction/syscall/seccomp.h"
#include "junction/syscall/syscall.h"

namespace junction {

// Pairs of (mount point, host path) for additional linux filesystems to be
// mounted.
const std::vector<std::pair<std::string, std::string>> linux_mount_points = {
    {"/tmp", "/tmp"},
    {"/home", "/home"},
    {"/dev/shm", "/dev/shm"},
};

pid_t linux_pid;

pid_t GetLinuxPid() { return linux_pid; }

JunctionCfg JunctionCfg::singleton_;

extern "C" void log_message_begin(uint64_t *cb_data) {
  if (base_init_done && thread_self() != NULL) {
    preempt_disable();
    *cb_data = GetFSBase();
    SetFSBase(perthread_read(runtime_fsbase));
  }
}

extern "C" void log_message_end(uint64_t *cb_data) {
  if (base_init_done && thread_self() != NULL) {
    SetFSBase(*cb_data);
    preempt_enable();
  }
}

namespace po = boost::program_options;

po::options_description GetOptions() {
  po::options_description desc("Junction options");
  desc.add_options()("help,h", "produce help message")(
      "chroot_path", po::value<std::string>()->default_value("/"),
      "chroot path to execute the binary from")(
      "fs_config_path", po::value<std::string>()->default_value(""),
      "file system configuration path")(
      "interpreter_path",
      po::value<std::string>()->implicit_value("")->default_value(
          CUSTOM_GLIBC_INTERPRETER_PATH),
      "use this custom interpreter for binaries")(
      "glibc_path",
      po::value<std::string>()->implicit_value("")->default_value(
          CUSTOM_GLIBC_DIR),
      "path to custom libc")(
      "ld_path",
      po::value<std::string>()->implicit_value("")->default_value(""),
      "a path to include in LD_LIBRARY_PATH")(
      "ld_preload",
      po::value<std::string>()->implicit_value("")->default_value(""),
      "location of ld preload library")(
      "env,E", po::value<std::vector<std::string>>()->multitoken(),
      "environment flags for binary")("port,p",
                                      po::value<int>()->default_value(42),
                                      "port number to setup control port on")(
      "strace,s", po::bool_switch()->default_value(false), "strace mode")(
      "restore,r", po::bool_switch()->default_value(false),
      "restore from a snapshot")("loglevel,l",
                                 po::value<int>()->default_value(LOG_DEBUG),
                                 "the maximum log level to print")(
      "snapshot-timeout,S", po::value<int>()->default_value(0),
      "snapshot timeout (in s) [0 means no automatic snapshot]")(
      "snapshot-prefix", po::value<std::string>()->default_value(""),
      "snapshot prefix path (will generate <prefix>.metadata and <prefix>.elf")(
      "stackswitch", po::bool_switch()->default_value(false),
      "use stack switching syscalls")(
      "madv_remap", po::bool_switch()->default_value(false),
      "zero memory when MADV_DONTNEED is used (intended for profiling)")(
      "cache_linux_fs", po::bool_switch()->default_value(false),
      "cache directory structure of the linux filesystem");
  ;
  return desc;
}

void JunctionCfg::PrintOptions() { std::cerr << GetOptions(); }

Status<void> JunctionCfg::FillFromArgs(int argc, char *argv[]) {
  po::options_description desc = GetOptions();
  po::variables_map vm;

  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
  } catch (std::exception &e) {
    std::cerr << "parse error: " << e.what() << std::endl;
    return MakeError(EINVAL);
  }

  if (vm.count("help")) return MakeError(EINVAL);

  chroot_path = vm["chroot_path"].as<std::string>();
  fs_config_path = vm["fs_config_path"].as<std::string>();
  interp_path = vm["interpreter_path"].as<std::string>();
  glibc_path = vm["glibc_path"].as<std::string>();
  ld_path = vm["ld_path"].as<std::string>();
  preload_path = vm["ld_preload"].as<std::string>();

  if (vm.count("env")) binary_envp = vm["env"].as<std::vector<std::string>>();

  strace = vm["strace"].as<bool>();
  stack_switching = vm["stackswitch"].as<bool>();
  max_loglevel = vm["loglevel"].as<int>();
  madv_remap = vm["madv_remap"].as<bool>();
  restore = vm["restore"].as<bool>();
  snapshot_prefix_ = vm["snapshot-prefix"].as<std::string>();
  cache_linux_fs_ = vm["cache_linux_fs"].as<bool>();
  snapshot_timeout_s_ = vm["snapshot-timeout"].as<int>();
  port_ = vm["port"].as<int>();
  if (snapshot_timeout_s_ && snapshot_prefix_.empty()) {
    std::cerr << "need a snapshot prefix if we are snapshotting" << std::endl;
    return MakeError(EINVAL);
  }

  return {};
}

void JunctionCfg::Print() {
  LOG(INFO) << "cfg: chroot_path = " << chroot_path;
  LOG(INFO) << "cfg: fs_config_path = " << fs_config_path;
  LOG(INFO) << "cfg: interpreter_path = " << interp_path;
  LOG(INFO) << "cfg: glibc_path = " << glibc_path;
  LOG(INFO) << "cfg: ld_path = " << ld_path;
  LOG(INFO) << "cfg: ld_preload = " << preload_path;
  for (std::string &s : binary_envp) LOG(INFO) << "env: " << s;
}

Status<std::shared_ptr<Process>> CreateTestProc() {
  Status<std::shared_ptr<Process>> p = CreateInitProcess();
  if (p) (*p)->CreateTestThread();
  return p;
}

Status<void> InitChroot() {
  const std::string_view &chroot_path = GetCfg().get_chroot_path();
  if (chroot_path != "/") {
    int ret = chroot(chroot_path.data());
    if (ret) return MakeError(ret);
  }
  return {};
}

std::vector<std::string> GetFsMounts() {
  std::string_view path = GetCfg().get_fs_config_path();
  if (path.empty()) return {};
  std::vector<std::string> paths;
  std::ifstream f(path.data());
  std::string line;
  while (std::getline(f, line)) paths.emplace_back(line);
  return paths;
}

Status<void> init() {
  // Make sure any one-time routines in the logger get run now.
  LOG(INFO) << "Initializing junction";
  GetCfg().Print();

  linux_pid = getpid();

  Status<void> ret = InitSignal();
  if (unlikely(!ret)) return ret;

  ret = SyscallInit();
  if (unlikely(!ret)) return ret;

  ret = InitChroot();
  if (unlikely(!ret)) return ret;

  ret = InitFs(linux_mount_points, GetFsMounts());
  if (unlikely(!ret)) return ret;

  ret = ShimJmpInit();
  if (unlikely(!ret)) return ret;

  ret = InitUnixTime();
  if (unlikely(!ret)) return ret;

  ret = InitControlServer();
  if (unlikely(!ret)) return ret;

  return init_seccomp();
}

}  // namespace junction
