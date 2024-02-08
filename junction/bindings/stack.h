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
inline struct stack& GetSyscallStack(thread_t* th = thread_self()) {
  return *th->stack;
}

// returns the bottom of a syscall stack (for nofp targets)
inline __nofp void* GetXsaveAreaNoFp(struct stack& stack) {
  return &stack.usable[STACK_PTR_SIZE - XSAVE_AREA_PTR_SIZE];
}

// returns the bottom of a syscall stack
inline void* GetXsaveArea(struct stack& stack) {
  return &stack.usable[STACK_PTR_SIZE - XSAVE_AREA_PTR_SIZE];
}

// returns the bottom of a syscall stack (for nofp targets)
inline __nofp uint64_t GetSyscallStackBottomNoFp(struct stack& stack) {
  uint64_t* rsp = &stack.usable[STACK_PTR_SIZE - XSAVE_AREA_PTR_SIZE - 1];
  return reinterpret_cast<uint64_t>(rsp);
}

// returns the bottom of a syscall stack
inline uint64_t GetSyscallStackBottom(struct stack& stack) {
  uint64_t* rsp = &stack.usable[STACK_PTR_SIZE - XSAVE_AREA_PTR_SIZE - 1];
  return reinterpret_cast<uint64_t>(rsp);
}

// returns the bottom of a thread's syscall stack
inline uint64_t GetSyscallStackBottom(thread_t* th = thread_self()) {
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

  return rsp >= ustack && rsp < ustack + RUNTIME_STACK_SIZE;
}

inline __nofp void assert_on_uintr_stack() {
  assert(!__builtin_ia32_testui());
  assert(on_uintr_stack());
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
__noreturn void RunOnStack(stack& stack, size_t reserved, Callable&& func,
                           Args&&... args)
  requires std::invocable<Callable, Args...>
{
  // Just run the function if we're already on the stack
  if (IsOnStack(stack)) {
    func(std::forward<Args>(args)...);
    std::unreachable();
  }

  using Data = rt::thread_internal::basic_data;
  using Wrapper = rt::thread_internal::Wrapper<Data, Callable, Args...>;

  size_t offset = STACK_PTR_SIZE -
                  (align_up(reserved, sizeof(uintptr_t)) / sizeof(uintptr_t));
  uint64_t rsp = reinterpret_cast<uint64_t>(&stack.usable[offset]);
  Wrapper* buf = AllocateOnStack<Wrapper>(&rsp);
  new (buf) Wrapper(std::forward<Callable>(func), std::forward<Args>(args)...);
  rsp = AlignDown(rsp, 16) - 8;

  auto f = [](void* arg) {
    Wrapper* w = reinterpret_cast<Wrapper*>(arg);
    w->Run();
  };

  nosave_switch(f, rsp, reinterpret_cast<uint64_t>(buf));
  std::unreachable();
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
  RunOnStack(GetSyscallStack(), XSAVE_AREA_SIZE, std::forward<Callable>(func),
             std::forward<Args>(args)...);
}

}  // namespace junction