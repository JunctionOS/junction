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
STRACE_LOG_BEFORE_RETURN = False

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
])

SKIP_STRACE_TARGET = ["vfork", "clone", "clone3", "rt_sigreturn"]

systabl_targets = [None for i in range(SYS_NR)]
systabl_strace_targets = [None for i in range(SYS_NR)]

systabl_targets[451] = "junction_fncall_stackswitch_enter"
systabl_targets[452] = "junction_fncall_stackswitch_enter_preserve_regs"
systabl_targets[453] = "junction_fncall_enter"
systabl_targets[454] = "junction_fncall_enter_preserve_regs"

for i in range(451, 455):
    systabl_strace_targets[i] = systabl_targets[i]

def genLogSyscallCall(pretty_name, with_ret):
    fn = ""
    if with_ret:
        fn += f"\n\tLogSyscall(ret, \"{pretty_name}\","
    else:
        fn += f"\n\tLogSyscall(\"{pretty_name}\","

    for i in range(6):
        if (pretty_name, i) not in STRACE_ARGS_THAT_ARE_PATHNAMES:
            fn += f"\n\t\treinterpret_cast<void *>(arg{i})"
        else:
            fn += f"\n\t\treinterpret_cast<char *>(arg{i})"
        if i < 5:
            fn += ","
    fn += ");"
    return fn

def emit_strace_target(pretty_name, function_name, output):
    fn = f"\nextern \"C\" __attribute__((cold)) uint64_t {function_name}_trace(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {'{'}"
    runsyscall_cmd = f"\n\tuint64_t ret = reinterpret_cast<sysfn_t>(&{function_name})(arg0, arg1, arg2, arg3, arg4, arg5);"

    is_exec_or_exit = "execve" in name or "exit" in name

    if STRACE_LOG_BEFORE_RETURN or is_exec_or_exit:
        fn += genLogSyscallCall(pretty_name, False)

    fn += runsyscall_cmd

    if STRACE_LOG_AFTER_RETURN and not is_exec_or_exit:
        fn += genLogSyscallCall(pretty_name, True)

    fn += "\n\treturn ret;"
    fn += "\n}"
    output.append(fn)
    return f"{function_name}_trace"


def emit_enosys_target(syscall_name, sysnr, output):
    wrapper_name = f"{syscall_name}_enosys"
    fn = f"""
    extern "C" __attribute__((cold)) long {wrapper_name}(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {'{'}
        LOG_ONCE(ERR) << "Unsupported system call {sysnr}:{syscall_name}";
        return -ENOSYS;
    {'}'}"""
    output.append(fn)
    return wrapper_name

def emit_errno_target(syscall_name, output, errno):
    wrapper_name = f"{syscall_name}_{errno.lower()}"
    fn = f"""
    extern "C" long {wrapper_name}(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {'{'}
        return -{errno.upper()};
    {'}'}"""
    output.append(fn)
    return wrapper_name

def emit_passthrough_target(syscall_name, sysnr, output):
    wrapper_name = f"{syscall_name}_forward"
    fn = f"""
    extern "C" long {wrapper_name}(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {'{'}
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
include_files += [f"junction/bindings/{f}.h" for f in ["sync", "log"]]

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
        elif len(ns) > 1 and ns[1] == "stub":
            target = emit_stub_target(name, dispatch_file)
        elif len(ns) > 1 and ns[1] == "custom":
            target = f"junction_entry_{name}"
        else:
            target = f"usys_{name}"

        assertion = f"""static_assert(is_valid_syscall_v<decltype(&{target})>, "usys functions must return 64-bit values");"""
        dispatch_file.append(assertion)

        systabl_targets[sysnr] = target
        if name not in SKIP_STRACE_TARGET:
            systabl_strace_targets[sysnr] = emit_strace_target(
                name, target, dispatch_file)
        else:
            systabl_strace_targets[sysnr] = target

for i in range(SYS_NR):
    if systabl_targets[i]:
        continue

    name = syscall_nr_to_name.get(i, f"SYS_{i}")
    target = emit_enosys_target(name, i, dispatch_file)
    systabl_targets[i] = target
    systabl_strace_targets[i] = emit_strace_target(name, target, dispatch_file)


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

# finish file and write it out
dispatch_file.append("}  // namespace junction")

with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(dispatch_file))
