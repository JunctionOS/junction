#include "junction/kernel/ksys.h"

static unsigned long dispatch(long sys_num, long arg0 = 0, long arg1 = 0,
                          long arg2 = 0, long arg3 = 0, long arg4 = 0,
                          long arg5 = 0) {
  // TODO(girfan): Dispatch to the appropriate handlers.
  return junction::ksys_default(sys_num, arg0, arg1, arg2, arg3, arg4, arg5);
}

extern "C" {

unsigned long int junction_syscall0(int number) { return dispatch(number); }

unsigned long int junction_syscall1(int number, long arg1) {
  return dispatch(number, arg1);
}

unsigned long int junction_syscall2(int number, long arg1, long arg2) {
  return dispatch(number, arg1, arg2);
}

unsigned long int junction_syscall3(int number, long arg1, long arg2,
                                    long arg3) {
  return dispatch(number, arg1, arg2, arg3);
}

unsigned long int junction_syscall4(int number, long arg1, long arg2, long arg3,
                                    long arg4) {
  return dispatch(number, arg1, arg2, arg3, arg4);
}

unsigned long int junction_syscall5(int number, long arg1, long arg2, long arg3,
                                    long arg4, long arg5) {
  return dispatch(number, arg1, arg2, arg3, arg4, arg5);
}

unsigned long int junction_syscall6(int number, long arg1, long arg2, long arg3,
                                    long arg4, long arg5, long arg6) {
  return dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);
}

}
