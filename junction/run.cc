#include <iostream>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/junction.hpp"
#include "junction/kernel/exec.h"

namespace junction {

void JunctionMain(int argc, char *argv[]) {
  // initialize junction
  Status<void> ret = init();
  BUG_ON(!ret);

  std::vector<std::string_view> envp = {
#ifndef CUSTOM_GLIBC_DIR
      "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu/",
#else
      "LD_LIBRARY_PATH=" CUSTOM_GLIBC_DIR ":/lib/x86_64-linux-gnu/",
      "LD_PRELOAD=" CUSTOM_GLIBC_PRELOAD,
#endif
  };
  std::vector<std::string_view> args = {};
  for (int i = 2; i < argc; i++) args.emplace_back(argv[i]);

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

int main(int argc, char *argv[]) {
  int ret;

  if (argc < 3) {
    std::cerr << "usage: [cfg_file] [binary] <args>" << std::endl;
    return -EINVAL;
  }

  ret = junction::rt::RuntimeInit(std::string(argv[1]),
                                  [=] { junction::JunctionMain(argc, argv); });

  if (ret) {
    std::cerr << "runtime failed to start" << std::endl;
    return ret;
  }

  return 0;
}
