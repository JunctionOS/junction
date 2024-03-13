#include <fcntl.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

constexpr char const *tmp_file = "/file";

int main(int argc, char *argv[]) {
  printf("Hello, world!\n");

  int tmp_fd = open(tmp_file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (tmp_fd == -1) {
    perror("linuxfd tmp open");
    return EXIT_FAILURE;
  }
  printf("tmp fd: %d\n", tmp_fd);

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");

  if (write(tmp_fd, "TEST", 4) != 4) {
    perror("write");
    return EXIT_FAILURE;
  }
  close(tmp_fd);

  int check_fd = open(tmp_file, O_RDONLY, 0644);
  if (check_fd == -1) {
    perror("linuxfd open");
    return EXIT_FAILURE;
  }
  printf("check fd: %d\n", check_fd);

  char check_fd_chars[4] = {0};
  ssize_t check_rd_ret = read(check_fd, &check_fd_chars, 4);
  if (check_rd_ret == -1) {
    perror("check read");
    return EXIT_FAILURE;
  } else if (check_rd_ret != 4) {
    fprintf(stderr, "failed to read the 4 bytes from the check file");
    return EXIT_FAILURE;
  }

  if (memcmp(check_fd_chars, "TEST", 4) != 0) {
    fprintf(stderr, "memcmp of the tmp file failed\n");
    return EXIT_FAILURE;
  }

  return 0;
}
