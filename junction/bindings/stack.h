#pragma once

extern "C" {
#include <signal.h>

#include "lib/caladan/runtime/defs.h"
}

#include <concepts>
#include <type_traits>

#include "junction/base/bits.h"
#include "junction/bindings/thread.h"

extern "C" [[noreturn]] void nosave_switch(thread_fn_t fn, uint64_t stack,
                                           uint64_t arg0);

extern "C" [[noreturn]] void nosave_switch_setui(void (*fn)(void), void* stack);

namespace junction {

inline uint64_t GetRsp() {
  uint64_t rsp;
  asm volatile("movq %%rsp, %0" : "=r"(rsp));
  return rsp;
}

inline bool IsOnStack(uint64_t cur_rsp, const stack_t& ss) {
  uint64_t sp = reinterpret_cast<uint64_t>(ss.ss_sp);

  return cur_rsp > sp && cur_rsp <= sp + ss.ss_size;
}

inline bool IsOnStack(uint64_t cur_rsp, const struct stack& ss) {
  uint64_t sp = reinterpret_cast<uint64_t>(&ss.usable[0]);

  return cur_rsp > sp && cur_rsp <= sp + RUNTIME_STACK_SIZE;
}

inline __nofp bool IsOnStackNoFp(uint64_t cur_rsp, const struct stack& ss) {
  uint64_t sp = reinterpret_cast<uint64_t>(&ss.usable[0]);

  return cur_rsp > sp && cur_rsp <= sp + RUNTIME_STACK_SIZE;
}

template <typename T>
inline bool IsOnStack(const T& ss) {
  return IsOnStack(GetRsp(), ss);
}

// returns the bottom of the Caladan runtime stack
inline uint64_t GetRuntimeStack() {
  return reinterpret_cast<uint64_t>(perthread_read(runtime_stack)) + 8;
}

// returns the bottom of the local thread's syscall stack
inline const struct stack& GetSyscallStack(const thread_t* th = thread_self()) {
  return *th->stack;
}

// returns the bottom of the local thread's syscall stack
inline uint64_t GetSyscallStackBottom() {
  uint64_t* rsp = &thread_self()->stack->usable[STACK_PTR_SIZE - 1];
  return reinterpret_cast<uint64_t>(rsp);
}

inline bool on_runtime_stack() {
  uint64_t rsp = GetRsp();
  return rsp <= GetRuntimeStack() &&
         rsp > GetRuntimeStack() - RUNTIME_STACK_SIZE;
}

inline void assert_on_runtime_stack() {
  assert_preempt_disabled();
  assert(on_runtime_stack());
}

template <typename T, size_t Alignment = alignof(T)>
T* AllocateOnStack(uint64_t* rsp) {
  // rsp is always 0 mod 8.
  if constexpr (Alignment > 8)
    *rsp = AlignDown(*rsp - sizeof(T), Alignment);
  else
    *rsp -= sizeof(T);
  return reinterpret_cast<T*>(*rsp);
}

template <typename T>
T* PushToStack(uint64_t* rsp, const T& src) {
  T* newT = AllocateOnStack<T>(rsp);
  new (newT) T(src);
  return newT;
}

template <typename Callable, typename... Args>
__noreturn void SwitchStack(uint64_t stack, Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  using Data = rt::thread_internal::basic_data;
  using Wrapper = rt::thread_internal::Wrapper<Data, Callable, Args...>;

  Wrapper* buf = AllocateOnStack<Wrapper>(&stack);
  new (buf) Wrapper(std::forward<Callable>(func), std::forward<Args>(args)...);
  stack = AlignDown(stack, 16) - 8;

  auto f = [](void* arg) {
    Wrapper* w = reinterpret_cast<Wrapper*>(arg);
    w->Run();
  };

  nosave_switch(f, stack, reinterpret_cast<uint64_t>(buf));
}

}  // namespace junction