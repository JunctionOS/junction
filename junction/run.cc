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

Status<std::shared_ptr<Process>> CreateFirstProcess(
    std::string_view path, const std::vector<std::string_view> &argv,
    const std::vector<std::string_view> &envp) {
  // Create the process object
  Status<std::shared_ptr<Process>> proc = CreateInitProcess();
  if (!proc) return MakeError(proc);

  // Create and insert STDIN, STDOUT, STDERR files
  std::shared_ptr<StdIOFile> fin =
      std::make_shared<StdIOFile>(kStdInFileNo, FileMode::kRead);
  std::shared_ptr<StdIOFile> fout =
      std::make_shared<StdIOFile>(kStdOutFileNo, FileMode::kWrite);
  std::shared_ptr<StdIOFile> ferr =
      std::make_shared<StdIOFile>(kStdErrFileNo, FileMode::kWrite);
  FileTable &ftbl = (**proc).get_file_table();
  ftbl.Insert(std::move(fin));
  ftbl.Insert(std::move(fout));
  ftbl.Insert(std::move(ferr));

  // Exec program image
  Status<ExecInfo> ret = Exec(**proc, (*proc)->get_mem_map(), path, argv, envp);
  if (!ret) {
    LOG(ERR) << "Failed to exec binary " << path << ": " << ret.error();
    return MakeError(ret);
  }

  Status<Thread *> tmp = (*proc)->CreateThreadMain();
  if (!tmp) return MakeError(tmp);
  Thread &th = **tmp;

  FunctionCallTf &entry = FunctionCallTf::CreateOnSyscallStack(th);
  thread_tf &tf = entry.GetFrame();
  tf.rdi = 0;
  tf.rsi = 0;
  tf.rdx = 0;
  tf.rcx = 0;
  tf.r8 = 0;
  tf.r9 = 0;
  tf.rsp = std::get<0>(*ret);
  tf.rip = std::get<1>(*ret);

  th.mark_enter_kernel();
  entry.MakeUnwinderSysret(th, th.GetCaladanThread()->tf);
  th.ThreadReady();
  return *proc;
}

std::pair<std::vector<std::string>, std::vector<std::string_view>> BuildEnvp() {
  // Initialize environment and arguments
  std::stringstream ld_path_s;
  ld_path_s << "LD_LIBRARY_PATH=";
  if (GetCfg().get_glibc_path().size()) ld_path_s << GetCfg().get_glibc_path();
  if (GetCfg().get_ld_path().size()) ld_path_s << ":" << GetCfg().get_ld_path();
  ld_path_s << ":/lib/x86_64-linux-gnu"
            << ":/usr/lib/x86_64-linux-gnu"
            << ":/usr/lib/jvm/java-17-openjdk-amd64/lib"
            << ":/usr/lib/jvm/java-18-openjdk-amd64/lib"
            << ":/usr/lib/jvm/java-19-openjdk-amd64/lib"
            << ":/usr/lib/jvm/java-21-openjdk-amd64/lib";
  std::string ld_path = ld_path_s.str();
  std::string preload_path("LD_PRELOAD=" + GetCfg().get_preload_path());

  const std::vector<std::string> &cfg_envp = GetCfg().get_binary_envp();

  std::vector<std::string> envp;
  envp.reserve(2 + cfg_envp.size());
  envp.emplace_back(std::move(ld_path));
  envp.emplace_back(std::move(preload_path));
  for (const std::string &s : cfg_envp) envp.emplace_back(s);

  std::vector<std::string_view> envp_view;
  envp_view.reserve(envp.size());
  for (const auto &p : envp) envp_view.emplace_back(p);
  return {std::move(envp), std::move(envp_view)};
}

void JunctionMain(int argc, char *argv[]) {
  EnableMemoryAllocation();

  std::vector<std::string_view> args;
  args.reserve(argc);
  for (int i = 0; i < argc; i++) args.emplace_back(argv[i]);

  // Initialize core junction services
  Status<void> ret = init();
  BUG_ON(!ret);

  Status<std::shared_ptr<Process>> proc;

  if (GetCfg().restoring()) {
    if (unlikely(argc < 2)) {
      LOG(ERR) << "Too few arguments for restore";
      syscall_exit(-1);
    }
    LOG(INFO) << "snapshot: restoring from snapshot (elf=" << args[1]
              << ", metadata=" << args[0] << ")";
    proc = RestoreProcess(args[0], args[1]);
    if (!proc) {
      LOG(ERR) << "Failed to restore proc";
      syscall_exit(-1);
    }
    LOG(INFO) << "snapshot: restored process with pid="
              << (*proc).get()->get_pid();
  } else if (!args.empty()) {
    auto [envp_s, envp_view] = BuildEnvp();
    // Create the first process
    proc = CreateFirstProcess(args[0], args, envp_view);
    if (!proc) syscall_exit(-1);
  }

  // setup automatic snapshot
  if (unlikely(!args.empty() && GetCfg().snapshot_timeout())) {
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

  if (!args.empty()) {
    // Drop reference so the process can properly destruct itself when done
    proc->reset();
  }

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
  } else if (strncmp(argv[1], "--help", 6) == 0 ||
             strncmp(argv[1], "-h", 2) == 0) {
    usage();
    return -EINVAL;
  }

  /* pick off runtime config file */
  std::string cfg_file(argv[1]);
  argv[1] = argv[0];
  argc--;
  argv++;

  int i = 1;
  bool found_dash = false;
  for (; i < argc; i++) {
    if (std::string(argv[i]) == "--") {
      found_dash = true;
      break;
    }
  }
  char **binary_args = nullptr;
  int binary_argc = argc - i - (found_dash ? 1 : 0);
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
