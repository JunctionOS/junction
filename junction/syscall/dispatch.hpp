// dispatch.hpp - dispatch a given syscall to its virtual syscall handler.

namespace junction {

void init_glibc_dispatcher();

unsigned long sys_dispatch(long syscall, long arg0 = 0, long arg1 = 0,
                           long arg2 = 0, long arg3 = 0, long arg4 = 0,
                           long arg5 = 0);

}  // namespace junction
