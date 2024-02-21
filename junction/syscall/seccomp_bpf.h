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

extern "C" {
#include <base/syscall.h>
}

#include <cstdint>

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

#ifndef __x86_64__
#error "Currently only supports x86-64"
#endif

#define REG_RESULT REG_RAX
#define REG_SYSCALL REG_RAX
#define REG_ARG0 REG_RDI
#define REG_ARG1 REG_RSI
#define REG_ARG2 REG_RDX
#define REG_ARG3 REG_R10
#define REG_ARG4 REG_R8
#define REG_ARG5 REG_R9
#define ARCH_NR AUDIT_ARCH_X86_64

#include "junction/kernel/ksys.h"

/* Compute the valid address range where syscalls are allowed from.
 * This is the address range of calls made from ksys.S
 */
static size_t ksys_start_addr = reinterpret_cast<size_t>(&junction::ksys_start);
static size_t ksys_end_addr = reinterpret_cast<size_t>(&junction::ksys_end);
static uint32_t ksys_start_addr_low = static_cast<uint32_t>(ksys_start_addr);
static uint32_t ksys_start_addr_hi =
    static_cast<uint32_t>(ksys_start_addr >> 32);
static uint32_t ksys_end_addr_low = static_cast<uint32_t>(ksys_end_addr);
static uint32_t ksys_end_addr_hi = static_cast<uint32_t>(ksys_end_addr >> 32);

static size_t base_syscall_start_addr =
    reinterpret_cast<size_t>(base_syscall_start);
static size_t base_syscall_end_addr =
    reinterpret_cast<size_t>(base_syscall_end);

static uint32_t base_start_lo = static_cast<uint32_t>(base_syscall_start_addr);
static uint32_t base_start_hi =
    static_cast<uint32_t>(base_syscall_start_addr >> 32);

static uint32_t base_end_lo = static_cast<uint32_t>(base_syscall_end_addr);
static uint32_t base_end_hi =
    static_cast<uint32_t>(base_syscall_end_addr >> 32);

#if 0
#define VALIDATE_ARCHITECTURE                             \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),            \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#endif

#define EXAMINE_SYSCALL BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr)

/* Steps to check if a syscall should be allowed:
 * 1:  Check the syscall number.
 * 2:  Check the instruction pointer's MSB 32 bits.
 * 3:  If they are greater than the MSB 32 bits of ksys_start, proceed.
 * 4:  Check the instruction pointer's LSB 32 bits.
 * 5:  If they are greater than the LSB 32 bits of ksys_start, proceed.
 * 6:  Check the instruction pointer's MSB 32 bits.
 * 7:  If they are greater than the MSB 32 bits of ksys_end, fail, else allow.
 * 8:  If they are equal to the MSB 32 bits of ksys_end, proceed.
 * 9:  Check the instruction pointer's LSB 32 bits.
 * 10: If they are greater than the LSB 32 bits of ksys_end, fail.
 * 11: If you have reached here, allow.
 * (Note: Address comparison of the instruction pointer and our start/end of the
 *        address range is done in chunks of 32 bits since BPF does not deal
 *        with 64 bits.)
 */
#define ALLOW_JUNCTION_SYSCALL(name)                                        \
  EXAMINE_SYSCALL, BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 11), \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, ksys_start_addr_hi, 0, 9),        \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, ksys_start_addr_low, 0, 7),       \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, ksys_end_addr_hi, 5, 0),          \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ksys_end_addr_hi, 1, 0),          \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),                         \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, ksys_end_addr_low, 1, 0),         \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

#define ALLOW_CALADAN_SYSCALL(name)                                         \
  EXAMINE_SYSCALL, BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 11), \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, base_start_hi, 0, 9),             \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, base_start_lo, 0, 7),             \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, base_end_hi, 5, 0),               \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, base_end_hi, 1, 0),               \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),                         \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),                           \
      BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, base_end_lo, 1, 0),               \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

#define ALLOW_ANY_JUNCTION_SYSCALL                                    \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),                         \
      BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, ksys_start_addr_hi, 0, 8),  \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),                     \
      BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, ksys_start_addr_low, 0, 6), \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_msb),                     \
      BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, ksys_end_addr_hi, 4, 0),    \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ksys_end_addr_hi, 0, 3),    \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ip_lsb),                     \
      BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, ksys_end_addr_low, 1, 0),   \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

#define ALLOW_SYSCALL(name)                                                \
  EXAMINE_SYSCALL, BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)

#define TRAP BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)
