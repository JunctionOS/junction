#include <fcntl.h>
#include <unistd.h>

#undef NDEBUG

#include <cassert>
#include <csignal>
#include <cstdio>

int main(int argc, char *argv[]) {
  int fd1 = open("/dev/zero", O_RDWR);
  int fd2 = open("/dev/null", O_RDWR);
  int fd3 = open("/dev/random", O_RDWR);
  int fd4 = open("/dev/urandom", O_RDWR);
  assert(fd1 >= 0);
  assert(fd2 >= 0);
  assert(fd3 >= 0);
  assert(fd4 >= 0);

  kill(getpid(), SIGSTOP);

  char buf[10];
  assert(read(fd1, buf, sizeof(buf)) == sizeof(buf));
  for (size_t i = 0; i < 10; i++) assert(buf[i] == '\0');

  assert(write(fd2, buf, sizeof(buf)) == sizeof(buf));
  assert(read(fd3, buf, sizeof(buf)) == sizeof(buf));
  assert(read(fd4, buf, sizeof(buf)) == sizeof(buf));
  printf("st_device test done!\n");
  return 0;
}
