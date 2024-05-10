extern "C" {
#include <fcntl.h>
}

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

class MemFSTest : public ::testing::Test {};

TEST_F(MemFSTest, OpenCreateReadWriteTest) {
  int d1 = mkdir("/memfs/foo", S_IRWXU);
  EXPECT_EQ(d1, 0);

  int d2 = mkdir("/memfs/foo/bar", S_IRWXU);
  EXPECT_EQ(d2, 0);

  int d3 = mkdir("/memfs/foo/cat", S_IRWXU);
  EXPECT_EQ(d3, 0);

  int f1 = open("/memfs/foo/cow.txt", O_RDWR | O_CREAT, S_IRWXU);
  EXPECT_GE(f1, 0);

  int fd = open("/memfs/foo/bar/test.txt", O_RDWR | O_CREAT, S_IRWXU);
  EXPECT_GE(fd, 0);

  int fd2 = open("/memfs/foo/bar/test.txt", O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
  EXPECT_EQ(fd2, -1);

  int ret = ftruncate(fd, 128);
  EXPECT_EQ(ret, 0);

  const char txt[] = "hello, world!";
  size_t len = sizeof(txt) / sizeof(char);
  ssize_t n = write(fd, txt, len);
  EXPECT_EQ(n, len);

  ret = close(f1);
  EXPECT_EQ(ret, 0);
  ret = close(fd);
  EXPECT_EQ(ret, 0);

  fd = open("/memfs/foo/bar/test.txt", O_RDONLY);
  EXPECT_GE(fd, 0);

  char content[128];

  len = 5;
  n = read(fd, content, len);
  EXPECT_EQ(n, len);

  ret = close(fd);
  EXPECT_EQ(ret, 0);
}
