#include "junction/bindings/runtime.h"

#include "junction/bindings/thread.h"

namespace junction::rt {

// initializes the runtime
int RuntimeInit(const std::string& cfg_path, std::function<void()> main_func) {
  using Data = thread_internal::basic_data;
  using Wrapper = thread_internal::Wrapper<Data, decltype(main_func)>;
  auto* func_copy = new Wrapper(std::move(main_func));
  return runtime_init(cfg_path.c_str(), thread_internal::ThreadTrampoline,
                      reinterpret_cast<void*>(func_copy));
}

}  // namespace junction::rt
