#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>

#include <cassert>
#include <csignal>
#include <cstdlib>

#include "snapshot_sys.h"

const char *elf_filename = "/tmp/entrypoint.elf";
const char *metadata_filename = "/tmp/entrypoint.metadata";

int main(int argc, char *argv[]) {
  // const char *elf;
  // const char *metadata;
  // elf = elf_filename;
  // metadata = metadata_filename;

  printf("Hello, world!\n");

  // Leave a pipe open for testing
  int fds[2];
  int ret = pipe(fds);
  assert(ret == 0);

  int fd = epoll_create(0);
  assert(fd >= 0);

  struct epoll_event ev = {EPOLLIN, 0};
  ret = epoll_ctl(fd, EPOLL_CTL_ADD, fds[0], &ev);
  assert(ret == 0);

  int linuxfd = open("test.txt", O_RDONLY, 0644);
  printf("linux fd: %d\n", linuxfd);
  if (linuxfd == -1) {
    printf("error: %s\n", strerror(errno));
  }

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");
  char p;
  ssize_t rd_ret = read(linuxfd, &p, 1);
  printf("read '%c' from test.txt: %zd\n", p, rd_ret);

  return 0;
}
