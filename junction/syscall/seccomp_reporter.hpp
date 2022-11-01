/*
 * syscall reporting example for seccomp
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#pragma once

#include "junction/syscall/seccomp_bpf.hpp"

/* Since this redfines "KILL_PROCESS" into a TRAP for the reporter hook,
 * we want to make sure it stands out in the build as it should not be
 * used in the final program.
 */
#warning "You've included the syscall reporter. Do not use in production!"
#undef KILL_PROCESS
#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)