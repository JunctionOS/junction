// utility functions for timing measurements

extern int cycles_per_us;
extern uint64_t start_tsc;

static inline void cpu_serialize(void) {
  asm volatile(
      "xorl %%eax, %%eax\n\t"
      "cpuid"
      :
      :
      : "%rax", "%rbx", "%rcx", "%rdx");
}

static inline uint64_t rdtsc(void) {
  uint32_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  return ((uint64_t)a) | (((uint64_t)d) << 32);
}

static inline uint64_t rdtscp(uint32_t *auxp) {
  uint32_t a, d, c;
  asm volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
  if (auxp) *auxp = c;
  return ((uint64_t)a) | (((uint64_t)d) << 32);
}

/**
 * microtime - gets the number of microseconds since the process started
 * This routine is very inexpensive, even compared to clock_gettime().
 */
static inline uint64_t microtime(void) {
  return (rdtsc() - start_tsc) / cycles_per_us;
}

int time_init(void);
