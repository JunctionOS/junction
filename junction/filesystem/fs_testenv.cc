#include <gtest/gtest.h>

#include "junction/junction.h"

/*
 * Performs a one-time environment setup for all FileSystem tests.
 */
class FileSystemTestEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
    if (!junction::init() || !junction::InitTestProc()) {
      throw std::runtime_error("Cannot initialize junction");
    }
  };
};

testing::Environment* const fs_test_env =
    testing::AddGlobalTestEnvironment(new FileSystemTestEnvironment);
