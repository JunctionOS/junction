#include "junction/filesystem/linuxfile.hpp"

// Needed for rdtsc.
extern "C" {
#include <sys/types.h>

#include "asm/ops.h"
}

#include <gtest/gtest.h>

#include <iostream>

using namespace junction;

/* Runs getpid() in a loop for a given number of iterations.
 * Logs the mean time taken for each call in number of cycles.
 */
pid_t _getpid_test_core(const long iters) {
  volatile pid_t pid;
  uint64_t tsc = rdtsc();
  for (long i = 0; i < iters; i++) {
    pid = getpid();
  }
  uint64_t tsc_elapsed = rdtsc() - tsc;
  std::cout << "getpid() = " << tsc_elapsed / iters << " cycles / syscall\n";
  return pid;
}

class DispatchTest : public ::testing::Test {};

/* This test benchmarks the performance of getpid() with/without junction,
 * depending on how the test binary was built.
 */
TEST_F(DispatchTest, GetPidPerfTest) {
  // Inputs/Outputs
  constexpr long iters = 100'000;

  // Action
  pid_t pid = _getpid_test_core(iters);

  // Test
#ifdef JUNCTION
  // Junction will shim the getpid() call and return 0.
  // TODO(girfan): Fix this when we return non-zero PIDs.
  EXPECT_EQ(0, pid);
  std::cout << "[JUNCTION]\n";
#else
  // When running without junction, we expect a non-zero (real) PID.
  EXPECT_NE(0, pid);
  std::cout << "[NATIVE]\n";
#endif  // JUNCTION
}
