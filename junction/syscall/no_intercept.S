/*
 * Copyright 2016-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

.global syscall_no_intercept;
.type   syscall_no_intercept, @function

.text

syscall_no_intercept:
/* First we check if the input arg was negative. If so, we don't execute
 * the syscall; we just return the "return address" of this function.
 * This is used when applying the seccomp filter such that *only* syscalls
 * originating from here will be allowed and everything else will be blocked.
 */
  test        %rdi, %rdi /* TODO(girfan): Check if this should be rax? */
  jge         1f
  call        0f
0:pop         %rax
  addq        $2f-0b, %rax /* Return the "return address" of this function */
  ret
/* This is where we execute the actual syscall.
 */
1:movq        %rdi, %rax  /* convert from linux ABI calling */
	movq        %rsi, %rdi  /* convention to syscall calling convention */
	movq        %rdx, %rsi
	movq        %rcx, %rdx
	movq        %r8, %r10
	movq        %r9, %r8
	movq        8(%rsp), %r9
	syscall
/* This is the return address we use as the only allowed address range to
 * make syscalls.
 */
2:ret

.size   syscall_no_intercept, .-syscall_no_intercept
