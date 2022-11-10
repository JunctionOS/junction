/* Benchmark for invoking syscalls.
 * Source:
 * https://github.com/torvalds/linux/blob/master/tools/testing/selftests/seccomp/seccomp_benchmark.c
 * Note: Modified from original version for use with junction.
 */
#define _GNU_SOURCE

extern "C" {
#include <assert.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Needed for rdtsc.
#include "asm/ops.h"
}

#include <stdexcept>

#include "junction/syscall/seccomp.hpp"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

uint64_t timing(clockid_t clk_id, unsigned long long samples) {
  unsigned long long i;
  pid_t pid;
  pid_t ret;

  pid = getpid();
  uint64_t tsc = rdtscp(NULL);
  for (i = 0; i < samples; i++) {
    ret = syscall(__NR_getpid);
  }
  auto tsc_elapsed = rdtscp(NULL) - tsc;
  return tsc_elapsed;
}

unsigned long long calibrate(void) {
  struct timespec start, finish;
  unsigned long long i, samples, step = 9973;
  pid_t pid, ret;
  int seconds = 15;

  printf("Calibrating sample size for %d seconds worth of syscalls ...\n",
         seconds);

  samples = 0;
  pid = getpid();
  clock_gettime(CLOCK_MONOTONIC, &start);
  do {
    for (i = 0; i < step; i++) {
      ret = syscall(__NR_getpid);
      assert(pid == ret);
    }
    clock_gettime(CLOCK_MONOTONIC, &finish);

    samples += step;
    i = finish.tv_sec - start.tv_sec;
    i *= 1000000000ULL;
    i += finish.tv_nsec - start.tv_nsec;
  } while (i < 1000000000ULL);

  return samples * seconds;
}

bool approx(int i_one, int i_two) {
  double one = i_one, one_bump = one * 0.01;
  double two = i_two, two_bump = two * 0.01;

  one_bump = one + MAX(one_bump, 2.0);
  two_bump = two + MAX(two_bump, 2.0);

  /* Equal to, or within 1% or 2 digits */
  if (one == two || (one > two && one <= two_bump) ||
      (two > one && two <= one_bump))
    return true;
  return false;
}

bool le(int i_one, int i_two) {
  if (i_one <= i_two) return true;
  return false;
}

long compare(const char *name_one, const char *name_eval, const char *name_two,
             unsigned long long one, bool (*eval)(int, int),
             unsigned long long two) {
  bool good;

  printf("\t%s %s %s (%lld %s %lld): ", name_one, name_eval, name_two,
         (long long)one, name_eval, (long long)two);
  if (one > INT_MAX) {
    printf("Miscalculation! Measurement went negative: %lld\n", (long long)one);
    return 1;
  }
  if (two > INT_MAX) {
    printf("Miscalculation! Measurement went negative: %lld\n", (long long)two);
    return 1;
  }

  good = eval(one, two);
  printf("%s\n", good ? "✔️" : "❌");

  return good ? 0 : 1;
}

int main(int argc, char *argv[]) {
  long ret, bits;
  unsigned long long samples, calc;
  uint64_t native, filter;

  setbuf(stdout, NULL);

  printf("Running on:\n");
  system("uname -a");

  printf("Current BPF sysctl settings:\n");
  /* Avoid using "sysctl" which may not be installed. */
  system("grep -H . /proc/sys/net/core/bpf_jit_enable");
  system("grep -H . /proc/sys/net/core/bpf_jit_harden");

  if (argc > 1)
    samples = strtoull(argv[1], NULL, 0);
  else
    samples = calibrate();

  printf("Benchmarking %llu syscalls...\n", samples);

  /* Native call */
  native = timing(CLOCK_PROCESS_CPUTIME_ID, samples) / samples;
  printf("getpid native: %lu cycles\n", native);

  if (junction::install_syscall_filter()) {
    printf("Error: install_syscall_filter()\n");
    return 1;
  }

  filter = timing(CLOCK_PROCESS_CPUTIME_ID, samples) / samples;
  printf("getpid filter: %lu cycles\n", filter);

  return 0;
}
