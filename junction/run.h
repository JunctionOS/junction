// run.h utilities for starting junction

#pragma once

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/junction.h"
#include "junction/kernel/exec.h"
#include "junction/kernel/stdiofile.h"

namespace junction {
namespace {

Status<std::shared_ptr<Process>> CreateFirstProcess(
    std::string_view path, const std::vector<std::string_view> &argv,
    const std::vector<std::string_view> &envp) {
  // Create the process object
  Status<std::shared_ptr<Process>> proc = CreateInitProcess();
  if (!proc) return MakeError(proc);

  // Create and insert STDIN, STDOUT, STDERR files
  std::shared_ptr<StdIOFile> fin =
      std::make_shared<StdIOFile>(kStdInFileNo, kModeRead);
  std::shared_ptr<StdIOFile> fout =
      std::make_shared<StdIOFile>(kStdOutFileNo, kModeWrite);
  std::shared_ptr<StdIOFile> ferr =
      std::make_shared<StdIOFile>(kStdErrFileNo, kModeWrite);
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

std::vector<std::string> BuildEnvp() {
  // Initialize environment and arguments
  std::stringstream ld_path_s;
  ld_path_s << "LD_LIBRARY_PATH=" << GetCfg().get_ld_path()
            << ":/lib/x86_64-linux-gnu"
            << ":/usr/lib/x86_64-linux-gnu"
            << ":/usr/lib/jvm/java-18-openjdk-amd64/lib"
            << ":/usr/lib/jvm/java-19-openjdk-amd64/lib"
            << ":/usr/lib/jvm/java-21-openjdk-amd64/lib";
  std::string ld_path = ld_path_s.str();
  std::stringstream preload_path_s;
  preload_path_s << "LD_PRELOAD=" << GetCfg().get_preload_path();
  std::string preload_path = preload_path_s.str();
  std::vector<std::string> envp = {
    ld_path,
    preload_path,
#if 0
                                        "LD_DEBUG=all"
#endif  // DEBUG
  };
  for (const std::string &s : GetCfg().get_binary_envp()) envp.emplace_back(s);

  return envp;
}

}  // anonymous namespace
}  // namespace junction
