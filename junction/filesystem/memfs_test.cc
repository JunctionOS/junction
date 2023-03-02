#include "junction/filesystem/memfs.h"

extern "C" {
#include <fcntl.h>
}

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"

using namespace junction;

class MemFSTest : public ::testing::Test {};

TEST_F(MemFSTest, OpenCreateReadWriteTest) {
  int d1 = open("/memfs/foo", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  EXPECT_GT(d1, 0);

  int d2 = open("/memfs/foo/bar", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  EXPECT_GT(d2, 0);

  int d3 = open("/memfs/foo/cat", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  EXPECT_GT(d3, 0);

  int d4 = open("/memfs/foo/dog", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  EXPECT_GT(d4, 0);

  int f1 = open("/memfs/foo/cow.txt", O_RDWR | O_CREAT, S_IRWXG);
  EXPECT_GT(f1, 0);

  int fd = open("/memfs/foo/bar/test.txt", O_RDWR | O_CREAT, S_IRWXG);
  EXPECT_GT(fd, 0);

  int ret = ftruncate(fd, 128);
  EXPECT_EQ(ret, 0);

  const char txt[] = "hello, world!";
  size_t len = sizeof(txt) / sizeof(char);
  ssize_t n = write(fd, txt, len);
  EXPECT_EQ(n, len);

  ret = close(d1);
  EXPECT_EQ(ret, 0);
  ret = close(d2);
  EXPECT_EQ(ret, 0);
  ret = close(d3);
  EXPECT_EQ(ret, 0);
  ret = close(d4);
  EXPECT_EQ(ret, 0);
  ret = close(f1);
  EXPECT_EQ(ret, 0);
  ret = close(fd);
  EXPECT_EQ(ret, 0);

  fd = open("/memfs/foo/bar/test.txt", O_RDONLY);
  EXPECT_GT(fd, 0);

  char *content = (char *)malloc(sizeof(char) * 128);
  EXPECT_NE(content, nullptr);

  len = 5;
  n = read(fd, content, len);
  EXPECT_EQ(n, len);

  free(content);

  ret = close(fd);
  EXPECT_EQ(ret, 0);
}
