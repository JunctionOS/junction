#include "junction/bindings/timer.h"

namespace junction::rt::timer_internal {

void TimerTrampoline(unsigned long arg) {
  auto *t = static_cast<timer_node *>(reinterpret_cast<void *>(arg));
  t->Run();
}

}  // namespace junction::rt::timer_internal
