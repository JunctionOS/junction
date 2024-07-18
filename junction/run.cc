#include "junction/run.h"

#include <iostream>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
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

  if (unlikely(GetCfg().mem_trace_timeout() > 0))
    (*proc)->get_mem_map().EnableTracing();

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
  MarkRuntimeReady();

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

    if (GetCfg().jif()) {
      LOG(INFO) << "snapshot: restoring from snapshot (jif=" << args[1]
                << ", metadata=" << args[0] << ")";
      proc = RestoreProcessFromJIF(args[0], args[1]);
    } else {
      LOG(INFO) << "snapshot: restoring from snapshot (elf=" << args[1]
                << ", metadata=" << args[0] << ")";
      proc = RestoreProcessFromELF(args[0], args[1]);
    }

    if (!proc) {
      LOG(ERR) << "Failed to restore proc";
      syscall_exit(-1);
    }
    LOG(INFO) << "snapshot: restored process with pid=" << (*proc)->get_pid();
  } else if (!args.empty()) {
    auto [_envp_s, envp_view] = BuildEnvp();
    // Create the first process
    proc = CreateFirstProcess(args[0], args, envp_view);
    if (!proc) syscall_exit(-1);
  }

  if (proc) {
    // setup teardown of tracer
    if (unlikely(GetCfg().mem_trace_timeout() > 0)) {
      rt::Spawn([p = *proc] mutable {
        rt::Sleep(Duration(GetCfg().mem_trace_timeout() * kSeconds));
        LOG(INFO) << "done sleeping, tracer reporting time!";
        auto trace_report = p->get_mem_map().EndTracing();
        if (unlikely(!trace_report)) {
          LOG(WARN) << "failed to collect trace report: "
                    << trace_report.error();
          return;
        }
        const auto ord_filename = GetCfg().mem_trace_path();
        std::stringstream ord;
        for (const auto &[time_us, page_addr, _str] : trace_report->accesses_us)
          ord << std::dec << time_us << ": 0x" << std::hex << page_addr << "\n";

        if (ord_filename.empty()) {
          LOG(INFO) << "memory trace:\n" << ord.view();
        } else {
          Status<KernelFile> ord_file = KernelFile::Open(
              ord_filename, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
          if (unlikely(!ord_file)) {
            LOG(WARN) << "failed to open ord file `" << ord_filename
                      << "`: " << ord_file.error();
            return;
          }
          auto report = ord.str();
          const auto ret = WriteFull(
              *ord_file,
              std::span(reinterpret_cast<const std::byte *>(report.c_str()),
                        report.size() + 1));
          if (unlikely(!ret)) {
            LOG(WARN) << "failed to write memory trace to `" << ord_filename
                      << "`: " << ret.error();
            return;
          }
          LOG(INFO) << "done reporting the memory trace";
        }
      });
    }

    // setup automatic snapshot
    if (unlikely(GetCfg().snapshot_on_stop())) {
      rt::Spawn([p = *proc] mutable {
        p->WaitForNthStop(GetCfg().snapshot_on_stop());
        std::string epath =
            std::string(GetCfg().get_snapshot_prefix()) + ".elf";
        std::string jif_path =
            std::string(GetCfg().get_snapshot_prefix()) + ".jif";
        std::string elf_metadata_path =
            std::string(GetCfg().get_snapshot_prefix()) + ".metadata";
        std::string jif_metadata_path =
            std::string(GetCfg().get_snapshot_prefix()) + ".jm";

        auto ret = (GetCfg().jif())
                       ? SnapshotPidToJIF(1, jif_metadata_path, jif_path)
                       : SnapshotPidToELF(1, elf_metadata_path, epath);
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
  proc->reset();
  LOG(INFO) << "waiting";
  rt::WaitForever();
  LOG(INFO) << "done waiting";
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
