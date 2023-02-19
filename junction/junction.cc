extern "C" {
#include <runtime/smalloc.h>
}

#include <boost/program_options.hpp>
#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfs.h"
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

  if (vm.count("interpreter_path"))
    interp_path = vm["interpreter_path"].as<std::string>();

  if (vm.count("ld_path")) ld_path = vm["ld_path"].as<std::string>();

  if (vm.count("ld_preload")) preload_path = vm["ld_preload"].as<std::string>();

  if (vm.count("env")) binary_envp = vm["env"].as<std::vector<std::string>>();

  return {};
}

void JunctionCfg::Print() {
  LOG(INFO) << "cfg: interpreter_path = " << interp_path;
  LOG(INFO) << "cfg: ld_path = " << ld_path;
  LOG(INFO) << "cfg: ld_preload = " << preload_path;
  for (std::string &s : binary_envp) LOG(INFO) << "env: " << s;
}

std::shared_ptr<LinuxFileSystemManifest> init_fs_manifest() {
  auto manifest = std::make_shared<LinuxFileSystemManifest>();
  const unsigned int flags = 0;
  const std::vector<std::string> filepaths(
      {"/lib64/*", "/lib/*", "/usr/*", "/home/*", "/etc/*"});
  for (const auto &filepath : filepaths) {
    manifest->Insert(filepath, flags);
  }
  return manifest;
}

Status<void> InitTestProc() {
  // Intentionally leak this memory
  Status<Process *> p = CreateProcess();
  (*p)->CreateTestThread();
  return {};
}

Status<void> init() {
  // Make sure any one-time routines in the logger get run now.
  LOG(INFO) << "Initializing junction";
  GetCfg().Print();
  std::shared_ptr<LinuxFileSystemManifest> manifest = init_fs_manifest();
  init_fs(new LinuxFileSystem(std::move(manifest)));

  Status<void> ret = SyscallInit();
  if (unlikely(!ret)) return ret;

  ret = ShimJmpInit();
  if (unlikely(!ret)) return ret;

  return init_seccomp();
}

}  // namespace junction

// Override global new and delete operators
inline void *__new(size_t size) {
  if (likely(base_init_done && thread_self()))
    return smalloc(size);
  else
    return malloc(size);
}

void *operator new(size_t size, const std::nothrow_t &nothrow_value) noexcept {
  return __new(size);
}

void *operator new(size_t size) throw() {
  void *ptr = __new(size);
  if (unlikely(size && !ptr)) throw std::bad_alloc();
  return ptr;
}

void *operator new[](size_t size) throw() {
  void *ptr = __new(size);
  if (unlikely(size && !ptr)) throw std::bad_alloc();
  return ptr;
}

void *operator new(size_t size, std::align_val_t align) throw() {
  // TODO(amb): need to implement alignment support
  void *ptr = __new(size);
  if (unlikely(size && !ptr)) throw std::bad_alloc();
  return ptr;
}

void operator delete(void *ptr) noexcept {
  if (!ptr) return;
  if (likely(base_init_done && thread_self()))
    sfree(ptr);
  else
    ;  // memory is being freed at teardown, probably ok to leak?
}

void operator delete[](void *ptr) noexcept {
  if (!ptr) return;
  if (likely(base_init_done && thread_self()))
    sfree(ptr);
  else
    ;  // memory is being freed at teardown, probably ok to leak?
}

void operator delete(void *ptr, std::align_val_t align) noexcept {
  // TODO(amb): need to implement alignment support
  if (!ptr) return;
  if (likely(base_init_done && thread_self()))
    sfree(ptr);
  else
    ;  // memory is being freed at teardown, probably ok to leak?
}
