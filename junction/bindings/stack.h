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

extern "C" [[noreturn]] void nosave_switch_preempt_enable(thread_fn_t fn,
                                                          uint64_t stack,
                                                          uint64_t arg0);

extern "C" [[noreturn]] void nosave_switch_setui(void (*fn)(void), void* stack);

extern "C" void _stack_switch_link(uint64_t arg0, uint64_t stack,
                                   thread_fn_t fn);

namespace junction {

inline constexpr size_t kStackAlign = 16;
inline constexpr size_t kRedzoneSize = 128;

__always_inline __nofp constexpr uintptr_t AlignForFunctionEntry(
    uintptr_t val) noexcept {
  return ((val - 8) & ~15ULL) | 8ULL;
}

inline uint64_t GetRsp() {
  uint64_t rsp;
  asm volatile("movq %%rsp, %0" : "=r"(rsp));
  return rsp;
}

__always_inline __nofp bool stack_is_aligned() {
  volatile int test_var __attribute__((aligned(kStackAlign)));
  uintptr_t addr;
  asm volatile("lea %1, %0" : "=r"(addr) : "m"(test_var));
  return addr % kStackAlign == 0;
}

__always_inline __nofp void assert_stack_is_aligned() {
  assert(stack_is_aligned());
}

__always_inline __nofp bool IsOnStack(uint64_t cur_rsp, uint64_t top,
                                      uint64_t bottom) {
  return cur_rsp > top && cur_rsp <= bottom;
}

__always_inline __nofp bool IsOnStack(uint64_t cur_rsp, const stack_t& ss) {
  uint64_t top = reinterpret_cast<uint64_t>(ss.ss_sp);
  return IsOnStack(cur_rsp, top, top + ss.ss_size);
}

__always_inline __nofp bool IsOnStack(uint64_t cur_rsp,
                                      const struct stack& ss) {
  uint64_t top = reinterpret_cast<uint64_t>(&ss.usable[0]);
  return IsOnStack(cur_rsp, top, top + RUNTIME_STACK_SIZE);
}

template <typename T>
__always_inline __nofp bool IsOnStack(const T& ss) {
  return IsOnStack(GetRsp(), ss);
}

// returns the bottom of the Caladan runtime stack
__always_inline __nofp uint64_t GetRuntimeStack() {
  return reinterpret_cast<uint64_t>(perthread_read(runtime_stack)) + 8;
}

__always_inline __nofp bool IsOnRuntimeStack(uint64_t rsp) {
  uint64_t ss = GetRuntimeStack();
  return rsp <= ss && rsp > ss - RUNTIME_STACK_SIZE;
}

// returns the bottom of the local thread's syscall stack
inline struct stack& GetSyscallStack(const thread_t* th = thread_self()) {
  return *th->stack;
}

__always_inline __nofp void* GetXsaveArea(struct stack& stack) {
  return &stack.usable[STACK_PTR_SIZE - XSAVE_AREA_PTR_SIZE];
}

// returns the bottom of a syscall stack
__always_inline __nofp uint64_t
GetSyscallStackBottom(const struct stack& stack) {
  const uint64_t* rsp = &stack.usable[STACK_PTR_SIZE - XSAVE_AREA_PTR_SIZE - 1];
  return reinterpret_cast<uint64_t>(rsp);
}

// returns the bottom of a thread's syscall stack
inline uint64_t GetSyscallStackBottom(const thread_t* th = thread_self()) {
  return GetSyscallStackBottom(*th->stack);
}

inline bool on_runtime_stack() {
  uint64_t rsp = GetRsp();
  return rsp <= GetRuntimeStack() &&
         rsp > GetRuntimeStack() - RUNTIME_STACK_SIZE;
}

inline __nofp bool on_uintr_stack() {
  uint64_t rsp;
  asm volatile("movq %%rsp, %0" : "=r"(rsp));

  uint64_t ustack = reinterpret_cast<uint64_t>(perthread_read(uintr_stack));
  ustack &= ~0x1UL;

  return IsOnStack(rsp, ustack - RUNTIME_STACK_SIZE, ustack);
}

inline __nofp void assert_on_uintr_stack() {
  assert(!__builtin_ia32_testui());
  assert(on_uintr_stack());
}

inline void assert_on_runtime_stack() { assert(on_runtime_stack()); }

template <typename T, size_t Alignment = alignof(T)>
T* AllocateOnStack(uint64_t* rsp) {
  assert(*rsp % 8 == 0);
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
__noreturn void RunOnStackAt(uint64_t rsp, Callable&& func, Args&&... args) {
  using Data = rt::thread_internal::basic_data;
  using Wrapper = rt::thread_internal::Wrapper<Data, Callable, Args...>;

  // Copy invocation data to the target stack after switching to the target
  // stack. This allows us to forward data to the syscall stack, which cannot be
  // used until it is active since it may race with a signal handler. The caller
  // must take care that the old stack/data remain valid until the function is
  // run, which means possibly disabling preemption in the case of per-kthread
  // stacks.
  Wrapper w(std::forward<Callable>(func), std::forward<Args>(args)...);
  rsp = AlignDown(rsp, 16) - 8;

  auto f = [](void* arg) {
    Wrapper* w = reinterpret_cast<Wrapper*>(arg);
    Wrapper wmove(std::move(*w));
    wmove.Run();
    std::unreachable();
  };

  nosave_switch(f, rsp, reinterpret_cast<uint64_t>(&w));
  std::unreachable();
}

template <typename Callable, typename... Args>
__noreturn void RunOnStack(stack& stack, size_t reserved, Callable&& func,
                           Args&&... args)
  requires std::invocable<Callable, Args...>
{
  // Just run the function if we're already on the stack
  if (IsOnStack(stack)) {
    func(std::forward<Args>(args)...);
    std::unreachable();
  }

  size_t offset = STACK_PTR_SIZE -
                  (align_up(reserved, sizeof(uintptr_t)) / sizeof(uintptr_t));
  uint64_t rsp = reinterpret_cast<uint64_t>(&stack.usable[offset]);
  RunOnStackAt(rsp, std::forward<Callable>(func), std::forward<Args>(args)...);
}

template <typename Callable, typename... Args>
auto CallOnStackAt(uint64_t rsp, Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  using Data = rt::thread_internal::basic_data;
  using Wrapper = rt::thread_internal::Wrapper<Data, Callable, Args...>;

  Wrapper w(std::forward<Callable>(func), std::forward<Args>(args)...);
  rsp = AlignDown(rsp, 16) - 8;

  auto f = [](void* arg) {
    Wrapper* w = reinterpret_cast<Wrapper*>(arg);
    w->Run();
  };

  _stack_switch_link(reinterpret_cast<uint64_t>(&w), rsp, f);
  return w.GetReturn();
}

template <typename Callable, typename... Args>
auto CallOnStack(stack& stack, size_t reserved, Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  // Just run the function if we're already on the stack
  if (IsOnStack(stack))
    return std::forward<Callable>(func)(std::forward<Args>(args)...);

  size_t offset = STACK_PTR_SIZE -
                  (align_up(reserved, sizeof(uintptr_t)) / sizeof(uintptr_t));
  uint64_t rsp = reinterpret_cast<uint64_t>(&stack.usable[offset]);
  return CallOnStackAt(rsp, std::forward<Callable>(func),
                       std::forward<Args>(args)...);
}

template <typename Callable, typename... Args>
__noreturn void RunOnStack(stack& stack, Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  assert(&stack != &GetSyscallStack());
  RunOnStack(stack, 0, std::forward<Callable>(func),
             std::forward<Args>(args)...);
}

template <typename Callable, typename... Args>
__noreturn void RunOnSyscallStack(Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  RunOnStack(GetSyscallStack(), 2 * XSAVE_AREA_SIZE + kRedzoneSize,
             std::forward<Callable>(func), std::forward<Args>(args)...);
}

template <typename Callable, typename... Args>
auto CallOnStack(stack& stack, Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  assert(&stack != &GetSyscallStack());
  return CallOnStack(stack, 0, std::forward<Callable>(func),
                     std::forward<Args>(args)...);
}

template <typename Callable, typename... Args>
auto CallOnSyscallStack(Callable&& func, Args&&... args)
  requires std::invocable<Callable, Args...>
{
  return CallOnStack(GetSyscallStack(), 2 * XSAVE_AREA_SIZE + kRedzoneSize,
                     std::forward<Callable>(func), std::forward<Args>(args)...);
}

}  // namespace junction