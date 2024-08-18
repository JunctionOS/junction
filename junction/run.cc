#include "junction/run.h"

#include <iostream>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/control/serverless.h"
#include "junction/fs/stdiofile.h"
#include "junction/junction.h"
#include "junction/kernel/exec.h"
#include "junction/run.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {

// Start trampoline with zero arg registers; some binaries need this
extern "C" void junction_exec_start(void *entry_arg);

}  // namespace

Status<std::shared_ptr<Process>> CreateFirstProcess(
    std::string_view path, std::vector<std::string_view> &argv,
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

  if (unlikely(GetCfg().mem_trace())) (*proc)->get_mem_map().EnableTracing();

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

  const std::vector<std::string> &cfg_envp = GetCfg().get_binary_envp();

  std::vector<std::string> envp;
  envp.reserve(2 + cfg_envp.size());
  envp.emplace_back(std::move(ld_path));
  if (GetCfg().get_preload_path().size())
    envp.emplace_back("LD_PRELOAD=" + GetCfg().get_preload_path());
  for (const std::string &s : cfg_envp) envp.emplace_back(s);

  std::vector<std::string_view> envp_view;
  envp_view.reserve(envp.size());
  for (const auto &p : envp) envp_view.emplace_back(p);
  return {std::move(envp), std::move(envp_view)};
}

void JunctionMain(int argc, char *argv[]) {
  timings().junction_main_start = Time::Now();
  MarkRuntimeReady();

  std::vector<std::string_view> args;
  args.reserve(argc);
  for (int i = 0; i < argc; i++) args.emplace_back(argv[i]);

  // Initialize core junction services
  Status<void> ret = init();
  if (unlikely(!ret)) {
    LOG(ERR) << "failed to initialize Junction: " << ret.error();
    syscall_exit(-1);
  }

  std::shared_ptr<Process> proc;
  std::string function_arg = GetCfg().GetArg("function_arg");

  if (GetCfg().restoring()) {
    if (unlikely(argc < 2)) {
      LOG(ERR) << "Too few arguments for restore";
      syscall_exit(-1);
    }

    Status<std::shared_ptr<Process>> tmp;

    LOG(INFO) << "snapshot: restoring from snapshot (data=" << args[1]
              << ", metadata=" << args[0] << ")";
    timings().restore_start = Time::Now();
    if (GetCfg().jif())
      tmp = RestoreProcessFromJIF(args[0], args[1]);
    else
      tmp = RestoreProcessFromELF(args[0], args[1]);

    if (unlikely(!tmp)) {
      LOG(ERR) << "Failed to restore proc: " << tmp.error();
      syscall_exit(-1);
    }

    proc = std::move(*tmp);
    LOG(INFO) << "snapshot: restored process with pid=" << proc->get_pid();
  } else if (!args.empty()) {
    if (!function_arg.empty()) {
      Status<void> ret = SetupServerlessChannel(0);
      if (unlikely(!ret)) {
        LOG(ERR) << "failed to setup channel";
        syscall_exit(-1);
      }
    }

    timings().exec_start = Time::Now();

    auto [_envp_s, envp_view] = BuildEnvp();
    // Create the first process
    Status<std::shared_ptr<Process>> tmp =
        CreateFirstProcess(args[0], args, envp_view);
    if (!tmp) syscall_exit(-1);
    proc = std::move(*tmp);
  }

  if (proc) {
    if (!function_arg.empty()) {
      rt::Spawn([p = proc, arg = std::move(function_arg)] mutable {
        if (GetCfg().restoring())
          RunRestored(std::move(p), 0, arg);
        else
          WarmupAndSnapshot(std::move(p), 0, arg);
      });
    } else if (unlikely(GetCfg().snapshot_on_stop())) {
      rt::Spawn([p = proc] mutable {
        p->WaitForNthStop(GetCfg().snapshot_on_stop());
        Status<void> ret = TakeSnapshot(p.get());
        if (!ret) {
          LOG(ERR) << "Failed to snapshot: " << ret.error();
          syscall_exit(-1);
        } else {
          LOG(INFO) << "snapshot successful!";
        }
        p->Signal(SIGCONT);
      });
    }
  }

  // Drop reference so the process can properly destruct itself when done
  proc.reset();
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

  std::string first_arg(argv[1]);
  if (first_arg == "--help" || first_arg == "-h") {
    usage();
    return -EINVAL;
  }

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
      first_arg, [=] { junction::JunctionMain(binary_argc, binary_args); });
  if (rtret) {
    std::cerr << "runtime failed to start" << std::endl;
    return rtret;
  }

  return 0;
}
