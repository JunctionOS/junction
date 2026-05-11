#!/usr/bin/env python3

import sys
import os

assert len(sys.argv) == 3

USYS_LIST = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

SYS_NR = 456

# Header files scanned in the given order to get a list of syscall numbers.
# The first file found is used.
SYSCALL_DEFS_FILES = [
    "/usr/include/asm/unistd_64.h",
    "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
]

"""
Use these flags to control whether strace logs before/after the syscall
executes (or both). Logging before the syscall occurs can be useful for
identifying where a thread is blocking.
"""
STRACE_LOG_AFTER_RETURN = True
STRACE_LOG_BEFORE_RETURN = True

STRACE_ARGS_THAT_ARE_PATHNAMES = set([
    ("openat", 1),
    ("open", 0),
    ("access", 0),
    ("readlink", 0),
    ("readlinkat", 1),
    ("newfstatat", 1),
    ("stat", 0),
    ("statfs", 0),
    ("mkdir", 0),
    ("mkdirat", 1),
    ("rmdir", 0),
    ("link", 0),
    ("link", 1),
    ("unlink", 0),
    ("unlinkat", 1),
    ("chown", 0),
    ("chmod", 0),
    ("execve", 0),
    ("execveat", 1),
    ("chdir", 0),
    ("renameat", 1),
    ("renameat2", 1),
    ("renameat", 3),
    ("renameat2", 3),
    ("rename", 0),
    ("rename", 1),
    ("symlink", 0),
    ("symlink", 1),
    ("symlinkat", 0),
    ("symlinkat", 2),
    ("statx", 1),
])

AT_FDS = [
    ("openat", 0),
    ("faccessat", 0),
    ("faccessat2", 0),
    ("mknodat", 0),
    ("renameat", 0),
    ("renameat", 2),
    ("renameat2", 0),
    ("renameat2", 2),
    ("unlinkat", 0),
    ("symlinkat", 1),
    ("newfstatat", 0),
    ("mkdirat", 0),
    ("linkat", 0),
    ("linkat", 2),
    ("readlinkat", 0),
    ("statx", 0),
]

TYPE_ARR = {
    p: 'reinterpret_cast<strace::PathName *>' for p in STRACE_ARGS_THAT_ARE_PATHNAMES
}

TYPE_ARR.update({
    p: 'static_cast<strace::AtFD>' for p in AT_FDS
})

VOIDP = 'reinterpret_cast<void *>'

TYPE_ARR.update({
    ("mmap", -1): VOIDP,
    ("brk", -1): VOIDP,
    ("mbind", 0): VOIDP,
    ("mmap", 2): 'static_cast<strace::ProtFlag>',
    ("mprotect", 2): 'static_cast<strace::ProtFlag>',
    ("pipe", 0): 'reinterpret_cast<strace::FDPair *>',
    ("pipe2", 0): 'reinterpret_cast<strace::FDPair *>',
    ("socketpair", 3): 'reinterpret_cast<strace::FDPair *>',
    ("mmap", 3): 'static_cast<strace::MMapFlag>',
    ("open", 1): 'static_cast<strace::OpenFlag>',
    ("openat", 2): 'static_cast<strace::OpenFlag>',
    ("rt_sigaction", 0): 'static_cast<strace::SignalNumber>',
    ("kill", 1): 'static_cast<strace::SignalNumber>',
    ("tgkill", 2): 'static_cast<strace::SignalNumber>',
    ("rt_tgsigqueueinfo", 2): 'static_cast<strace::SignalNumber>',
    ("madvise", 2): 'static_cast<strace::MAdviseHint>',
    ("futex", 1): 'static_cast<strace::FutexOp>',
    ("ioctl", 1): 'static_cast<strace::IoctlOp>',
    ("fcntl", 1): 'static_cast<strace::FcntlOp>',
    ("socket", 0): 'static_cast<strace::SocketDomain>',
    ("socket", 1): 'static_cast<strace::SocketType>',
    ("send", 3): 'static_cast<strace::MessageFlag>',
    ("sendto", 3): 'static_cast<strace::MessageFlag>',
    ("sendmsg", 2): 'static_cast<strace::MessageFlag>',
    ("recv", 3): 'static_cast<strace::MessageFlag>',
    ("recvfrom", 3): 'static_cast<strace::MessageFlag>',
    ("recvmsg", 2): 'static_cast<strace::MessageFlag>',
    ("epoll_ctl", 1): 'static_cast<strace::EpollOp>',
    ("unshare", 0): 'static_cast<strace::CloneFlag>',
    ("prctl", 0): 'static_cast<strace::PrctlOp>',
    ("rt_sigprocmask", 0): 'static_cast<strace::SigProcMaskOp>',
    ("waitpid", 2): 'static_cast<strace::WaitOptions>',
    ("waitid", 3): 'static_cast<strace::WaitOptions>',
    ("statx", 3): 'static_cast<strace::StatxMask>',
    ("statx", 2): 'static_cast<strace::AtFlag>',
    ("getsockopt", 1): 'static_cast<strace::SockoptLevel>',
    ("setsockopt", 1): 'static_cast<strace::SockoptLevel>',
})

SKIP_STRACE_TARGET = [
    "exit",
    "exit_group",
    "vfork",
    "clone",
    "clone3",
    "rt_sigreturn"]

ARRAY_ARGS = {
    ("poll", 0) : 1,
    ("epoll_wait", 1) : 2,
    ("epoll_pwait", 1) : 2,
    ("epoll_pwait2", 1) : 2,
    ("recvmmsg", 1) : 2,
    ("writev", 1) : 2,
    ("readv", 1) : 2,
    ("pwritev", 1) : 2,
    ("pwritev2", 1) : 2,
    ("preadv", 1) : 2,
}

BYTE_SPAN_ARGS = {
    ("read", 1): 2,
    ("write", 1) : 2,
    ("pread64", 1) : 2,
    ("pwrite64", 1) : 2,
    ("pread", 1) : 2,
    ("pwrite", 1) : 2,
    ("recv", 1): 2,
    ("recvfrom", 1): 2,
    ("send", 1): 2,
    ("sendto", 1): 2,
}

systabl_targets = [None for i in range(SYS_NR)]
systabl_strace_targets = [None for i in range(SYS_NR)]

systabl_targets[451] = "junction_fncall_stackswitch_enter"
systabl_targets[452] = "junction_fncall_stackswitch_enter_preserve_regs"
systabl_targets[453] = "junction_fncall_enter"
systabl_targets[454] = "junction_fncall_enter_preserve_regs"
systabl_targets[455] = "junction_fncall_stackswitch_enter_eax"

for i in range(451, 456):
    systabl_strace_targets[i] = systabl_targets[i]

def genLogSyscallCall(pretty_name, with_ret, fnname):
    ret = ""

    fn = "\n\t{"
    for i in range(6):
        if (pretty_name, i) in ARRAY_ARGS:
            fn += f"\n\t\tstrace::ArrayInfo arrinfo{i} = {{reinterpret_cast<void *>(arg{i}), static_cast<ssize_t>(arg{ARRAY_ARGS[(pretty_name, i)]})}};"
        elif (pretty_name, i) in BYTE_SPAN_ARGS:
            fn += f"\n\t\tstrace::ByteSpan binfo{i} = {{reinterpret_cast<void *>(arg{i}), static_cast<size_t>(arg{BYTE_SPAN_ARGS[(pretty_name, i)]})}};"

    if with_ret:
        if (pretty_name, -1) in TYPE_ARR:
            ret = f"{TYPE_ARR[(pretty_name, -1)]}(ret), "
        else:
            ret = "ret, "

    fn += f"\n\t\tLogSyscall(ctx, {ret}\"{pretty_name}\", &{fnname},"
    for i in range(6):
        if (pretty_name, i) in ARRAY_ARGS:
            fn += f"\n\t\t\t(&arrinfo{i})"
        elif (pretty_name, i) in BYTE_SPAN_ARGS:
            fn += f"\n\t\t\t(&binfo{i})"
        elif (pretty_name, i) not in TYPE_ARR:
            fn += f"\n\t\t\t(arg{i})"
        else:
            fn += f"\n\t\t\t{TYPE_ARR[(pretty_name, i)]}(arg{i})"
        if i < 5:
            fn += ","
    fn += ");"
    fn += "\n\t}"
    return fn


def emit_strace_target(pretty_name, function_name, output, sysnr):
    fn = f"\nextern \"C\" __attribute__((cold)) int64_t {function_name}_trace(int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5) {'{'}"
    fn += "\n\tassert_stack_is_aligned();"
    fn += f"\n\tstrace::SyscallCtx ctx(std::make_tuple(arg0, arg1, arg2, arg3, arg4, arg5), {sysnr});"
    runsyscall_cmd = f"\n\tint64_t ret = reinterpret_cast<sysfn_t>(&{function_name})(arg0, arg1, arg2, arg3, arg4, arg5);"

    if STRACE_LOG_BEFORE_RETURN:
        fn += genLogSyscallCall(pretty_name, False, function_name)

    fn += runsyscall_cmd

    fn += f"\n\tctx.retval = ret;"

    if STRACE_LOG_AFTER_RETURN:
        fn += genLogSyscallCall(pretty_name, True, function_name)

    fn += "\n\treturn ret;"
    fn += "\n}"
    output.append(fn)
    return f"{function_name}_trace"


def emit_fsbase_sanitize_wrap(handler_name, wrapper_name, output):
    """Mirror strace: dispatch to the real C handler via sysfn_t, never junction_fncall_*."""
    fn = f"""
extern "C" __attribute__((cold)) int64_t {wrapper_name}(
    int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4,
    int64_t arg5) {{
  assert_stack_is_aligned();
  FsbaseSanitizeEnter();
  int64_t ret = reinterpret_cast<sysfn_t>(&{handler_name})(
      arg0, arg1, arg2, arg3, arg4, arg5);
  FsbaseSanitizeExit();
  return ret;
}}"""
    output.append(fn)


# Table entries that use assembly syscall dispatch (must not be wrapped in C++).
JUNCTION_FNCALL_HANDLERS = frozenset([
    "junction_fncall_stackswitch_enter",
    "junction_fncall_stackswitch_enter_preserve_regs",
    "junction_fncall_enter",
    "junction_fncall_enter_preserve_regs",
    "junction_fncall_stackswitch_enter_eax",
])


def emit_enosys_target(syscall_name, sysnr, output):
    wrapper_name = f"{syscall_name}_enosys"
    fn = f"""
    extern "C" __attribute__((cold)) long {wrapper_name}
                                           (long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
        '{'}
        LOG_ONCE(ERR) << "Unsupported system call {sysnr}:{syscall_name}";
        return -ENOSYS;
    {'}'}"""
    output.append(fn)
    return wrapper_name


def emit_errno_target(syscall_name, output, errno):
    wrapper_name = f"{syscall_name}_{errno.lower()}"
    fn = f"""
    extern "C" long {wrapper_name}
        (long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
        '{'}
        return -{errno.upper()};
    {'}'}"""
    output.append(fn)
    return wrapper_name


def emit_passthrough_target(syscall_name, sysnr, output):
    wrapper_name = f"{syscall_name}_forward"
    fn = f"""
    extern "C" long {wrapper_name}
        (long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
        '{'}
        return ksys_default(arg0, arg1, arg2, arg3, arg4, arg5, {sysnr});
    {'}'}"""
    output.append(fn)
    return wrapper_name


def emit_stub_target(syscall_name, output):
    wrapper_name = f"{syscall_name}_stub"
    fn = f"""
    extern "C" long {wrapper_name}(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {'{'}
        return 0;
    {'}'}"""
    output.append(fn)
    return wrapper_name


def gen_syscall_dict():
    syscall_defs_file = None
    for file in SYSCALL_DEFS_FILES:
        if os.path.exists(file):
            syscall_defs_file = file
            break
    assert (
        syscall_defs_file is not None), "No header file found for determining syscall numbers"
    with open(syscall_defs_file) as f:
        dat = f.read().splitlines()
    syscall_nr_to_name = {}
    syscall_name_to_nr = {}
    for line in dat:
        ls = line.strip().split("#define __NR_")
        if len(ls) > 1:
            name, nr = ls[1].split()
            syscall_nr_to_name[int(nr)] = name
            syscall_name_to_nr[name] = int(nr)
    return syscall_nr_to_name, syscall_name_to_nr


syscall_nr_to_name, syscall_name_to_nr = gen_syscall_dict()

filename = os.path.basename(OUTPUT_FILE)
dispatch_file = [
    f"// {filename} - Generated by systbl.py - do not modify",
    "",
    ""]

include_files = [
    f"junction/syscall/{f}.h" for f in ["systbl", "strace", "syscall", "entry"]]
include_files += [f"junction/bindings/{f}.h" for f in ["sync", "log", "stack"]]

for file in include_files:
    dispatch_file.append(f"#include \"{file}\"")

# Make sure we are in sync with the header
dispatch_file += [f"static_assert(SYS_NR == {SYS_NR});"]
dispatch_file += ["namespace junction {"]

# Helper code to validate usys functions.
dispatch_file += ["""
#include <type_traits>

// Helper to extract function signature
template <typename>
struct function_traits;

// Specialization for function pointers
template <typename R, typename... Args>
struct function_traits<R(*)(Args...)> {
    using return_type = R;
};

// Helper alias
template <typename T>
using return_type_t = typename function_traits<T>::return_type;

// Trait to check if the return type is either void or 8 bytes in size
template <typename T, typename = void>
struct is_void_or_8bytes : std::false_type {};

template <typename T>
struct is_void_or_8bytes<T, std::enable_if_t<std::is_void_v<T>>> : std::true_type {};

template <typename T>
struct is_void_or_8bytes<T, std::enable_if_t<!std::is_void_v<T> && sizeof(T) == 8>> : std::true_type {};

// Helper variable template
template <typename T>
constexpr bool is_valid_syscall_v = is_void_or_8bytes<return_type_t<T>>::value;

"""]

with open(USYS_LIST) as f:
    for line in f:
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        ns = name.split(":::", 2)
        name = ns[0]

        # Junction custom kernel entry point
        if len(ns) > 1 and ns[1] == "custom":
            assert len(ns) > 2, "custom syscall needs a number"
            nr = int(ns[2])
            assert nr not in syscall_nr_to_name, "syscall number must be unique"
            syscall_name_to_nr[name] = nr

        if name not in syscall_name_to_nr:
            continue
        sysnr = syscall_name_to_nr.get(name)

        if len(ns) > 1 and ns[1] == "passthrough":
            target = emit_passthrough_target(name, sysnr, dispatch_file)
        elif len(ns) > 1 and ns[1] == "enotsup":
            target = emit_errno_target(name, dispatch_file, "ENOTSUP")
        elif len(ns) > 1 and ns[1] == "eopnotsup":
            target = emit_errno_target(name, dispatch_file, "EOPNOTSUPP")
        elif len(ns) > 1 and ns[1] == "enosys_quiet":
            target = emit_errno_target(name, dispatch_file, "ENOSYS")
        elif len(ns) > 1 and ns[1] == "stub":
            target = emit_stub_target(name, dispatch_file)
        elif len(ns) > 1 and ns[1] == "custom":
            target = f"junction_entry_{name}"
        else:
            target = f"usys_{name}"

        assertion = f"""static_assert(is_valid_syscall_v<decltype(&{
            target})>, "usys functions must return 64-bit values");"""
        dispatch_file.append(assertion)

        systabl_targets[sysnr] = target
        if name not in SKIP_STRACE_TARGET:
            systabl_strace_targets[sysnr] = emit_strace_target(
                name, target, dispatch_file, sysnr)
        else:
            systabl_strace_targets[sysnr] = target

for i in range(SYS_NR):
    if systabl_targets[i]:
        continue

    name = syscall_nr_to_name.get(i, f"SYS_{i}")
    target = emit_enosys_target(name, i, dispatch_file)
    systabl_targets[i] = target
    systabl_strace_targets[i] = emit_strace_target(name, target, dispatch_file, i)

systabl_fsbase_targets = [None for i in range(SYS_NR)]
for i in range(SYS_NR):
    handler = systabl_targets[i]
    name = syscall_nr_to_name.get(i)
    if handler in JUNCTION_FNCALL_HANDLERS or (
            name is not None and name in SKIP_STRACE_TARGET):
        systabl_fsbase_targets[i] = handler
        continue
    w = f"syscall_fsbase_wrap_{i}"
    emit_fsbase_sanitize_wrap(handler, w, dispatch_file)
    systabl_fsbase_targets[i] = w

# generate the sysfn table
dispatch_file += [f"sysfn_t sys_tbl[SYS_NR] = {'{'}"]
for i, entry in enumerate(systabl_targets):
    idx = f"__NR_{syscall_nr_to_name[i]}" if i in syscall_nr_to_name else i
    dispatch_file.append(f"\t[{idx}] = reinterpret_cast<sysfn_t>(&{entry}),")
dispatch_file.append("};")

# generate the table of names for debugging
dispatch_file += [f"const char *syscall_names[SYS_NR] = {'{'}"]
for i in range(SYS_NR):
    idx = f"__NR_{syscall_nr_to_name[i]}" if i in syscall_nr_to_name else i
    name = syscall_nr_to_name.get(i, f"unknown_syscall_{i}")
    dispatch_file.append(f"\t[{idx}] = \"{name}\",")
dispatch_file.append("};")

# generate the sysfn-strace table
dispatch_file += [f"sysfn_t sys_tbl_strace[SYS_NR] = {'{'}"]
for i, entry in enumerate(systabl_strace_targets):
    idx = f"__NR_{syscall_nr_to_name[i]}" if i in syscall_nr_to_name else i
    dispatch_file.append(f"\t[{idx}] = reinterpret_cast<sysfn_t>(&{entry}),")
dispatch_file.append("};")

# fsbase sanitize: wraps sys_tbl targets (same composition pattern as strace)
dispatch_file += [f"sysfn_t sys_tbl_fsbase_sanitize[SYS_NR] = {'{'}"]
for i, entry in enumerate(systabl_fsbase_targets):
    idx = f"__NR_{syscall_nr_to_name[i]}" if i in syscall_nr_to_name else i
    dispatch_file.append(f"\t[{idx}] = reinterpret_cast<sysfn_t>(&{entry}),")
dispatch_file.append("};")

# finish file and write it out
dispatch_file.append("}  // namespace junction")

with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(dispatch_file))
