extern "C" {
#include <time.h>
}

#include <iostream>

#include "timing.h"

#define CACHE_LINE_SIZE 64
#define __aligned(x) __attribute__((aligned(x)))

int cycles_per_us __aligned(CACHE_LINE_SIZE);
uint64_t start_tsc;

/* derived from DPDK */
static int time_calibrate_tsc(void) {
  /* TODO: New Intel CPUs report this value in CPUID */
  struct timespec sleeptime = {.tv_nsec = (long int)5E8}; /* 1/2 second */
  struct timespec t_start, t_end;

  cpu_serialize();
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
    uint64_t ns, end, start;
    double secs;

    start = rdtsc();
    nanosleep(&sleeptime, NULL);
    clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
    end = rdtscp(NULL);
    ns = ((t_end.tv_sec - t_start.tv_sec) * 1E9);
    ns += (t_end.tv_nsec - t_start.tv_nsec);

    secs = (double)ns / 1000;
    cycles_per_us = (uint64_t)((end - start) / secs);
    std::cout << "time: detected " << cycles_per_us << " ticks / us"
              << std::endl;

    /* record the start time of the binary */
    start_tsc = rdtsc();
    return 0;
  }

  return -1;
}

/**
 * time_init - global time initialization
 *
 * Returns 0 if successful, otherwise fail.
 */
int time_init(void) { return time_calibrate_tsc(); }
