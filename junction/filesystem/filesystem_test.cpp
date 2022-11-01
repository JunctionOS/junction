#include <fcntl.h>
#include <gtest/gtest.h>

#include <string>

#include "junction/filesystem/file.hpp"

TEST(FileSystemTest, FileCreationTest) {
  const std::string filepath = "test.txt";
  const bool is_dir = false;
  int fd = open(filepath.c_str(), O_RDONLY);

  EXPECT_NE(fd, -1);
}
