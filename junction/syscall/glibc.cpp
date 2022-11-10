// glibc.cpp - provides definitions for syscall intercept points from glibc.

#include "junction/kernel/ksys.h"
#include "junction/syscall/dispatch.hpp"

using namespace junction;

extern "C" {
unsigned long int junction_syscall0(int number) { return sys_dispatch(number); }

unsigned long int junction_syscall1(int number, long arg1) {
  return sys_dispatch(number, arg1);
}

unsigned long int junction_syscall2(int number, long arg1, long arg2) {
  return sys_dispatch(number, arg1, arg2);
}

unsigned long int junction_syscall3(int number, long arg1, long arg2,
                                    long arg3) {
  return sys_dispatch(number, arg1, arg2, arg3);
}

unsigned long int junction_syscall4(int number, long arg1, long arg2, long arg3,
                                    long arg4) {
  return sys_dispatch(number, arg1, arg2, arg3, arg4);
}

unsigned long int junction_syscall5(int number, long arg1, long arg2, long arg3,
                                    long arg4, long arg5) {
  return sys_dispatch(number, arg1, arg2, arg3, arg4, arg5);
}

unsigned long int junction_syscall6(int number, long arg1, long arg2, long arg3,
                                    long arg4, long arg5, long arg6) {
  return sys_dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);
}
}
