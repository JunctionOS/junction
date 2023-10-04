#include <iostream>

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
  Status<Thread *> ret = Exec(**proc, (*proc)->get_mem_map(), path, argv, envp);
  if (!ret) {
    LOG(ERR) << "Failed to exec binary: " << ret.error();
    return MakeError(ret);
  }

  (*ret)->ThreadReady();

  return *std::move(proc);
}

}  // namespace

void JunctionMain(int argc, char *argv[]) {
  // Initialize core junction services
  EnableMemoryAllocation();
  Status<void> ret = init();
  BUG_ON(!ret);

  // Initialize environment and arguments
  std::stringstream ld_path_s;
  ld_path_s << "LD_LIBRARY_PATH=" << GetCfg().get_ld_path()
            << ":/lib/x86_64-linux-gnu"
            << ":/usr/lib/x86_64-linux-gnu"
            << ":/usr/lib/jvm/java-18-openjdk-amd64/lib"
            << ":/usr/lib/jvm/java-19-openjdk-amd64/lib";
  std::string ld_path = ld_path_s.str();
  std::stringstream preload_path_s;
  preload_path_s << "LD_PRELOAD=" << GetCfg().get_preload_path();
  std::string preload_path = preload_path_s.str();
  std::vector<std::string_view> envp = {ld_path, preload_path,
#ifdef DEBUG
                                        "LD_DEBUG=all"
#endif  // DEBUG
  };
  for (const std::string &s : GetCfg().get_binary_envp()) envp.emplace_back(s);
  std::vector<std::string_view> args = {};
  for (int i = 0; i < argc; i++) args.emplace_back(argv[i]);

  // Create the first process
  Status<std::shared_ptr<Process>> proc =
      CreateFirstProcess(args[0], args, envp);
  BUG_ON(!proc);

  // Drop reference so the process can properly destruct itself when done
  (*proc).reset();

  Process::WaitAll();
  return;
}

}  // namespace junction

void usage() {
  std::cerr
      << "usage: <cfg_file> [junction options]... -- <binary> [binary args]..."
      << std::endl;
  std::cerr << junction::GetCfg().GetOptions();
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    usage();
    return -EINVAL;
  }

  /* pick off runtime config file */
  std::string cfg_file(argv[1]);
  argv[1] = argv[0];
  argc--;
  argv++;

  int i;
  for (i = 1; i < argc; i++)
    if (std::string(argv[i]) == "--") break;

  if (i >= argc - 1) {
    std::cerr << "Missing binary to launch" << std::endl;
    usage();
    return -EINVAL;
  }

  char **binary_args = &argv[i + 1];
  int binary_argc = argc - i - 1;
  int junction_argc = i;

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
