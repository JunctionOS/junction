#include "junction/junction.h"

#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/vfs.h"
#include "junction/junction.h"
#include "junction/kernel/fs.h"
#include "junction/kernel/proc.h"
#include "junction/shim/backend/init.h"
#include "junction/syscall/seccomp.h"
#include "junction/syscall/syscall.h"

namespace junction {

JunctionCfg &GetCfg() {
  static JunctionCfg cfg;
  return cfg;
}

namespace po = boost::program_options;

po::options_description JunctionCfg::GetOptions() {
  po::options_description desc("Junction options");
  desc.add_options()("help", "produce help message")(
      "chroot_path", po::value<std::string>()->implicit_value(""),
      "chroot path to execute the binary from")(
      "fs_config_path", po::value<std::string>()->implicit_value(""),
      "file system configuration path")(
      "interpreter_path", po::value<std::string>()->implicit_value(""),
      "use this custom interpreter for binaries")(
      "ld_path", po::value<std::string>()->implicit_value(""),
      "a path to include in LD_LIBRARY_PATH, use to inject a custom libc")(
      "ld_preload", po::value<std::string>()->implicit_value(""),
      "location of ld preload library")(
      "env,E", po::value<std::vector<std::string>>()->multitoken(),
      "environment flags for binary");
  return desc;
}

Status<void> JunctionCfg::FillFromArgs(int argc, char *argv[]) {
  po::options_description desc = GetOptions();
  po::variables_map vm;

  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
  } catch (std::exception &e) {
    std::cerr << "parse error: " << e.what() << std::endl;
    return MakeError(-1);
  }

  if (vm.count("help")) return MakeError(0);

  if (vm.count("chroot_path"))
    chroot_path = vm["chroot_path"].as<std::string>();

  if (vm.count("fs_config_path"))
    fs_config_path = vm["fs_config_path"].as<std::string>();

  if (vm.count("interpreter_path"))
    interp_path = vm["interpreter_path"].as<std::string>();

  if (vm.count("ld_path")) ld_path = vm["ld_path"].as<std::string>();

  if (vm.count("ld_preload")) preload_path = vm["ld_preload"].as<std::string>();

  if (vm.count("env")) binary_envp = vm["env"].as<std::vector<std::string>>();

  return {};
}

void JunctionCfg::Print() {
  LOG(INFO) << "cfg: chroot_path = " << chroot_path;
  LOG(INFO) << "cfg: fs_config_path = " << fs_config_path;
  LOG(INFO) << "cfg: interpreter_path = " << interp_path;
  LOG(INFO) << "cfg: ld_path = " << ld_path;
  LOG(INFO) << "cfg: ld_preload = " << preload_path;
  for (std::string &s : binary_envp) LOG(INFO) << "env: " << s;
}

Status<void> InitTestProc() {
  // Intentionally leak this memory
  Status<Process *> p = CreateProcess();
  (*p)->CreateTestThread();
  return {};
}

Status<void> InitChroot() {
  const std::string_view &chroot_path = GetCfg().get_chroot_path();
  if (chroot_path != "/") {
    int ret = chroot(chroot_path.data());
    if (ret) return MakeError(ret);
  }
  return {};
}

Status<void> InitFS() {
  const std::string_view &fs_config_path = GetCfg().get_fs_config_path();
  FileSystem *fs;
  if (fs_config_path.empty()) {
    fs = new VFS();
  } else {
    fs = new VFS(fs_config_path);
  }
  init_fs(fs);
  return {};
}

Status<void> init() {
  // Make sure any one-time routines in the logger get run now.
  LOG(INFO) << "Initializing junction";
  GetCfg().Print();

  Status<void> ret = InitFS();
  if (unlikely(!ret)) return ret;

  ret = SyscallInit();
  if (unlikely(!ret)) return ret;

  ret = InitChroot();
  if (unlikely(!ret)) return ret;

  ret = ShimJmpInit();
  if (unlikely(!ret)) return ret;

  return init_seccomp();
}

}  // namespace junction
