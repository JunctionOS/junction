#include <gtest/gtest.h>

#ifdef JUNCTION
#include "junction/junction.hpp"
#endif  // JUNCTION

/*
 * Performs a one-time environment setup for all Syscall tests.
 */
class SyscallTestEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
#ifdef JUNCTION
    if (!junction::init()) {
      throw std::runtime_error("Cannot initialize junction");
    }
#endif  // JUNCTION
  };
};

testing::Environment* const fs_test_env =
    testing::AddGlobalTestEnvironment(new SyscallTestEnvironment);
