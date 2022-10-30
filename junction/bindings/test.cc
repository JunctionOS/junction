extern "C" {
#include <base/log.h>
#include <base/stddef.h>
}

#include <string>

#include "log.h"
#include "net.h"
#include "rcu.h"
#include "runtime.h"
#include "sync.h"
#include "thread.h"
#include "timer.h"

namespace junction {

namespace {

constexpr int kTestValue = 10;

void foo(int arg) {
  if (arg != kTestValue) BUG();
}

void func(const std::string arg1, const std::string arg2,
          const std::string arg3) {
  LOG(INFO) << "func called with arg1 '" << arg1 << "', arg2 '" << arg2
            << "', arg3 '" << arg3 << "'";
  if (arg1 != "foobar") BUG();
  if (arg2 != "baz") BUG();
  if (arg3 != "bar") BUG();
}

void MainHandler() {
  std::string str = "captured!";
  int i = kTestValue;
  int j = kTestValue;

  rt::Spawn([=] {
    LOG(INFO) << "hello from ThreadSpawn()! '" << str << "'";
    foo(i);
  });

  rt::Spawn([&] {
    LOG(INFO) << "hello from ThreadSpawn()! '" << str << "'";
    foo(i);
  });

  rt::Spawn(func, "foobar", "baz", "bar");

  rt::Yield();
  rt::Sleep(1 * rt::kMilliseconds);

  auto th = rt::Thread([&] {
    LOG(INFO) << "hello from rt::Thread! '" << str << "'";
    foo(i);
    j *= 2;
  });
  th.Join();

  if (j != kTestValue * 2) BUG();
  rt::RuntimeExit(EXIT_SUCCESS);
}

}  // namespace

}  // namespace junction

using namespace junction;

int main(int argc, char* argv[]) {
  int ret;

  if (argc < 2) {
    printf("arg must be config file\n");
    return -EINVAL;
  }

  ret = rt::RuntimeInit(argv[1], MainHandler);
  if (ret) {
    LOG(ERR) << "failed to start runtime";
    return ret;
  }
  return 0;
}
