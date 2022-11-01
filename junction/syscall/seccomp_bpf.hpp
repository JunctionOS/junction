/*
 * seccomp example for x86 (32-bit and 64-bit) with BPF macros
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Will Drewry <wad@chromium.org>
 *  Kees Cook <keescook@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#pragma once

#define _GNU_SOURCE 1
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#endif

// https://lore.kernel.org/all/1400799936-26499-7-git-send-email-keescook@chromium.org/
// https://github.com/torvalds/linux/commit/c2e1f2e30daa551db3c670c0ccfeab20a540b9e1
#ifndef PR_SECCOMP_EXT
#define PR_SECCOMP_EXT 43
#endif

#ifndef SECCOMP_EXT_ACT
#define SECCOMP_EXT_ACT 1
#endif

#ifndef SECCOMP_EXT_ACT_TSYNC
#define SECCOMP_EXT_ACT_TSYNC 2
#endif

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#ifdef HAVE_LINUX_SECCOMP_H
#include <linux/seccomp.h>
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2         /* uses user-supplied filter. */
#define SECCOMP_RET_KILL 0x00000000U  /* kill the task immediately */
#define SECCOMP_RET_TRAP 0x00030000U  /* disallow and force a SIGSYS */
#define SECCOMP_RET_ALLOW 0x7fff0000U /* allow */
struct seccomp_data {
  int nr;
  __u32 arch;
  __u64 instruction_pointer;
  __u64 args[6];
};
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
#define ip_msb (offsetof(struct seccomp_data, instruction_pointer) + 4)
#define ip_lsb (offsetof(struct seccomp_data, instruction_pointer) + 0)

#if defined(__i386__)
#define REG_RESULT REG_EAX
#define REG_SYSCALL REG_EAX
#define REG_ARG0 REG_EBX
#define REG_ARG1 REG_ECX
#define REG_ARG2 REG_EDX
#define REG_ARG3 REG_ESI
#define REG_ARG4 REG_EDI
#define REG_ARG5 REG_EBP
#define ARCH_NR AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define REG_RESULT REG_RAX
#define REG_SYSCALL REG_RAX
#define REG_ARG0 REG_RDI
#define REG_ARG1 REG_RSI
#define REG_ARG2 REG_RDX
#define REG_ARG3 REG_R10
#define REG_ARG4 REG_R8
#define REG_ARG5 REG_R9
#define ARCH_NR AUDIT_ARCH_X86_64
#else
#warning "Platform does not support seccomp filter yet"
#define REG_SYSCALL 0
#define ARCH_NR 0
#endif

#define VALIDATE_ARCHITECTURE                             \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),            \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr)

#define ALLOW_RANGE_SYSCALL(name, low, hi)            \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),         \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, low, 0, 3), \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),     \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, hi, 0, 1),  \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),   \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)

#define ALLOW_SYSCALL(name)                               \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)

#define TRAP BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)
