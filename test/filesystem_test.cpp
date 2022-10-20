#include <fcntl.h>
#include <gtest/gtest.h>

#include <string>

#include "filesystem/file.hpp"

// Open a file from a valid fd.
TEST(JunctionTest, FileCreationTest) {
  const std::string filepath = "test.txt";
  const bool is_dir = false;
  int fd = open(filepath.c_str(), O_RDONLY);

  EXPECT_NE(fd, -1);

  junction::File file(fd, filepath, is_dir);
}
