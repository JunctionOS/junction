#include "junction/run.h"

#include <iostream>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/junction.h"
#include "junction/kernel/exec.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {

// Start trampoline with zero arg registers; some binaries need this
extern "C" void junction_exec_start(void *entry_arg);

}  // namespace

void JunctionMain(int argc, char *argv[]) {
  EnableMemoryAllocation();

  std::vector<std::string_view> args = {};
  for (int i = 0; i < argc; i++) args.emplace_back(argv[i]);

  // Initialize core junction services
  Status<void> ret = init();
  BUG_ON(!ret);

  Status<std::shared_ptr<Process>> proc;

  if (GetCfg().restoring()) {
    BUG_ON(args.size() < 2);
    LOG(INFO) << "snapshot: restoring from snapshot (elf=" << args[1]
              << ", metadata=" << args[0] << ")";
    proc = RestoreProcess(args[0], args[1]);
    if (!proc) {
      LOG(ERR) << "Failed to restore proc";
      return;
    }
    LOG(INFO) << "snapshot: restored process with pid="
              << (*proc).get()->get_pid();
  } else if (!args.empty()) {
    auto envp = BuildEnvp();
    std::vector<std::string_view> envp_view;
    envp_view.reserve(envp.size());
    for (auto const &s : envp) envp_view.emplace_back(s);
    // Create the first process
    proc = CreateFirstProcess(args[0], args, envp_view);
  }

  BUG_ON(!proc);

  std::shared_ptr<Process> proc_ptr = *proc;

  // setup automatic snapshot
  if (proc_ptr && unlikely(GetCfg().snapshot_timeout())) {
    rt::Spawn([] {
      // Wait x seconds
      rt::Sleep(Duration(GetCfg().snapshot_timeout() * kSeconds));
      LOG(INFO) << "done sleeping, snapshot time!";
      std::string mtpath =
          std::string(GetCfg().get_snapshot_prefix()) + ".metadata";
      std::string epath = std::string(GetCfg().get_snapshot_prefix()) + ".elf";

      auto ret = SnapshotPid(1, mtpath, epath);
      if (!ret) {
        LOG(ERR) << "Failed to snapshot: " << ret.error();
        syscall_exit(-1);
      } else {
        LOG(INFO) << "snapshot successful!";
      }
    });
  }

  // Drop reference so the process can properly destruct itself when done
  proc_ptr.reset();

  rt::WaitForever();
}

}  // namespace junction

void usage() {
  std::cerr
      << "usage: <cfg_file> [junction options]... -- <binary> [binary args]..."
      << std::endl;
  junction::JunctionCfg::PrintOptions();
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage();
    return -EINVAL;
  }

  /* pick off runtime config file */
  std::string cfg_file(argv[1]);
  argv[1] = argv[0];
  argc--;
  argv++;

  int i = 1;
  for (; i < argc; i++)
    if (std::string(argv[i]) == "--") break;

  if (i == argc) i = argc - 1;

  char **binary_args = nullptr;
  int binary_argc = argc - i - 1;
  int junction_argc = i;

  if (binary_argc > 0) {
    binary_args = &argv[i + 1];
  }

  junction::Status<void> ret =
      junction::GetCfg().FillFromArgs(junction_argc, argv);
  if (!ret) {
    usage();
    return MakeCError(ret);
  }

  int rtret = junction::rt::RuntimeInit(
      cfg_file, [=] { junction::JunctionMain(binary_argc, binary_args); });
  if (rtret) {
    std::cerr << "runtime failed to start" << std::endl;
    return rtret;
  }

  return 0;
}
