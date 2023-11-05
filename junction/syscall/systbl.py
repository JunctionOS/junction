#!/usr/bin/env python3

import sys
import os

assert len(sys.argv) == 3

USYS_LIST = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

SYS_NR = 454
JUNCTION_TF_OFF = 416

# Header files scanned in the given order to get a list of syscall numbers.
# The first file found is used.
SYSCALL_DEFS_FILES = [
	"/usr/include/asm/unistd_64.h",
	"/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
]


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
])

def emit_strace_target(pretty_name, function_name, output):
	fn = f"\nextern \"C\" uint64_t {function_name}_trace(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {'{'}"
	runsyscall_cmd = f"\n\tuint64_t ret = reinterpret_cast<sysfn_t>(&{function_name})(arg0, arg1, arg2, arg3, arg4, arg5);"
	if "execve" not in name and "exit" not in name:
		fn += runsyscall_cmd
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

	if "execve" in name or "exit" in name:
		fn += runsyscall_cmd

	fn += "\n\treturn ret;"
	fn += "\n}"
	output.append(fn)
	return f"{function_name}_trace"

def emit_enosys_target(syscall_name, sysnr, output):
	wrapper_name = f"{syscall_name}_enosys"
	fn = f"""
	extern "C" long {wrapper_name}(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {'{'}
		LOG_ONCE(ERR) << "Unsupported system call {sysnr}:{syscall_name}";
		return -ENOSYS;
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

def emit_regular_target(syscall_name, output):
	wrapper_name = f"{syscall_name}_entry"
	fn = f"""
	extern "C" uint64_t {wrapper_name}(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {'{'}
		usyscall_on_enter();
		uint64_t ret = reinterpret_cast<sysfn_t>(&usys_{syscall_name})(arg0, arg1, arg2, arg3, arg4, arg5);
		usyscall_on_leave(ret);
		return ret;
	{'}'}"""
	output.append(fn)
	return wrapper_name

def emit_trapframe_save_entry(function_target, output):
	wrapper_name = f"{function_target}_tfsave"
	fn = f"""

	static_assert(JUNCTION_TF_OFF == {JUNCTION_TF_OFF});

	static_assert(offsetof(thread_tf, rdi) == 0);
	static_assert(offsetof(thread_tf, rsi) == 8);
	static_assert(offsetof(thread_tf, rdx) == 16);
	static_assert(offsetof(thread_tf, rcx) == 24);
	static_assert(offsetof(thread_tf, r8) == 32);
	static_assert(offsetof(thread_tf, r9) == 40);
	static_assert(offsetof(thread_tf, r10) == 48);


	static_assert(offsetof(thread_tf, rbx) == 64);
	static_assert(offsetof(thread_tf, rbp) == 72);
	static_assert(offsetof(thread_tf, r12) == 80);
	static_assert(offsetof(thread_tf, r13) == 88);
	static_assert(offsetof(thread_tf, r14) == 96);
	static_assert(offsetof(thread_tf, r15) == 104);
	static_assert(offsetof(thread_tf, rip) == 120);
	static_assert(offsetof(thread_tf, rsp) == 128);

	extern "C" void {wrapper_name}(void);
	asm(R"(

	.globl {wrapper_name}
	.type {wrapper_name}, @function
	{wrapper_name}:
	movq %gs:__perthread___self(%rip), %r11
	addq ${JUNCTION_TF_OFF}, %r11

	/* save registers */

	movq    %rdi, 0(%r11)
	movq    %rsi, 8(%r11)
	movq    %rdx, 16(%r11)
	movq    %rcx, 24(%r11)
	movq    %r8, 32(%r11)
	movq    %r9, 40(%r11)

	movq    %r10, 48(%r11)

	movq    %rbx, 64(%r11)
	movq    %rbp, 72(%r11)
	movq    %r12, 80(%r11)
	movq    %r13, 88(%r11)
	movq    %r14, 96(%r11)
	movq    %r15, 104(%r11)
	movq	%rsp, 128(%r11)

	/* save RIP */
	movq    (%rsp), %r10
	movq    %r10, 120(%r11)

	jmp {function_target}
	)");
	"""
	output.append(fn)
	return wrapper_name


def gen_syscall_dict():
	syscall_defs_file = None
	for file in SYSCALL_DEFS_FILES:
		if os.path.exists(file):
			syscall_defs_file = file
			break
	assert (syscall_defs_file is not None), "No header file found for determining syscall numbers"
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
dispatch_file = [f"// {filename} - Generated by systbl.py - do not modify", "", ""]
dispatch_file += ["#include \"junction/syscall/systbl.h\"", "#include \"junction/bindings/log.h\""]
dispatch_file += ["#include \"junction/syscall/strace.h\"",]
dispatch_file += ["#include \"junction/syscall/syscall.h\"",]
dispatch_file += ["#include \"junction/syscall/entry.h\"",]
dispatch_file += ["#include \"junction/bindings/sync.h\"",]

dispatch_file += [f"static_assert(SYS_NR == {SYS_NR});"] # Make sure we are in sync with the header
dispatch_file += ["namespace junction {"]

systabl_targets = [None for i in range(SYS_NR)]
systabl_strace_targets = [None for i in range(SYS_NR)]

with open(USYS_LIST) as f:
	for line in f:
		name = line.strip()
		if not name or name.startswith("#"):
			continue
		ns = name.split(":::", 2)
		name = ns[0]
		if name not in syscall_name_to_nr:
			continue
		sysnr = syscall_name_to_nr.get(name)

		if name == "rt_sigreturn":
			systabl_targets[sysnr] = "usys_rt_sigreturn_enter"
			systabl_strace_targets[sysnr] = "usys_rt_sigreturn_enter"
		elif len(ns) > 1 and ns[1] == "savetrapframe":
			main_entry = emit_regular_target(name, dispatch_file)
			strace_entry =  emit_strace_target(name, main_entry, dispatch_file)
			systabl_targets[sysnr] = emit_trapframe_save_entry(main_entry, dispatch_file)
			systabl_strace_targets[sysnr]  = emit_trapframe_save_entry(strace_entry, dispatch_file)
		else:
			if len(ns) > 1 and ns[1] == "passthrough":
				target = emit_passthrough_target(name, sysnr, dispatch_file)
			else:
				target = emit_regular_target(name, dispatch_file)

			systabl_targets[sysnr] = target
			systabl_strace_targets[sysnr] = emit_strace_target(name, target, dispatch_file)

for i in range(SYS_NR):
	if systabl_targets[i]:
		continue

	name = syscall_nr_to_name.get(i, f"SYS_{i}")
	target = emit_enosys_target(name, i, dispatch_file)
	systabl_targets[i] = target
	systabl_strace_targets[i] = emit_strace_target(name, target, dispatch_file)


# TODO: fix
systabl_targets[451] = "junction_fncall_stackswitch_enter"
systabl_targets[452] = "junction_fncall_stackswitch_clone_enter"
systabl_targets[453] = "junction_fncall_stackswitch_vfork_enter"
systabl_strace_targets[451] = "junction_fncall_stackswitch_enter"
systabl_strace_targets[452] = "junction_fncall_stackswitch_clone_enter"
systabl_strace_targets[453] = "junction_fncall_stackswitch_vfork_enter"

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

