#include <iostream>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/junction.h"
#include "junction/kernel/exec.h"

namespace junction {

void JunctionMain(int argc, char *argv[]) {
  // initialize junction
  Status<void> ret = init();
  BUG_ON(!ret);

  std::stringstream ld_path_s;
  ld_path_s << "LD_LIBRARY_PATH=" << GetCfg().get_ld_path()
            << ":/lib/x86_64-linux-gnu/";
  std::string ld_path = ld_path_s.str();

  std::stringstream preload_path_s;
  preload_path_s << "LD_PRELOAD=" << GetCfg().get_preload_path();
  std::string preload_path = preload_path_s.str();

  std::vector<std::string_view> envp = {ld_path, preload_path,
#ifdef DEBUG
                                        "LD_DEBUG=all"
#endif  // DEBUG
  };

  std::vector<std::string_view> args = {};
  for (int i = 0; i < argc; i++) args.emplace_back(argv[i]);

  Status<thread_t *> th = Exec(args[0], args, envp);
  if (!th) {
    LOG(ERR) << "Failed to exec binary: " << th.error();
    return;
  }

  thread_ready(*th);

  // Wait forever... (the binary will directly call GROUP_EXIT for now)
  rt::WaitForever();
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
    return ret.error().code();
  }

  int rtret = junction::rt::RuntimeInit(
      cfg_file, [=] { junction::JunctionMain(binary_argc, binary_args); });

  if (rtret) {
    std::cerr << "runtime failed to start" << std::endl;
    return rtret;
  }

  return 0;
}
