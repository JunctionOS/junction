#include <fcntl.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

constexpr uint8_t ELF_MAGIC[4] = {0x7f, 'E', 'L', 'F'};

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0); // make stdout unbuffered
  printf("Hello, world!\n");

  int self_fd = open(argv[0], O_RDONLY, 0644);
  if (self_fd == -1) {
    perror("linuxfd open");
    return EXIT_FAILURE;
  }
  printf("self fd: %d\n", self_fd);

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");
  char self_fd_chars[4] = {0};
  ssize_t self_rd_ret = read(self_fd, &self_fd_chars, 4);
  if (self_rd_ret == -1) {
    perror("self read");
    return EXIT_FAILURE;
  } else if (self_rd_ret != 4) {
    fprintf(stderr, "failed to read the 4 bytes from the self file");
    return EXIT_FAILURE;
  }
  printf("read %c%c%c%c [%hhx %hhx %hhx %hhx] from %s: %zd\n", self_fd_chars[0],
         self_fd_chars[1], self_fd_chars[2], self_fd_chars[3], self_fd_chars[0],
         self_fd_chars[1], self_fd_chars[2], self_fd_chars[3], argv[0],
         self_rd_ret);

  if (memcmp(self_fd_chars, ELF_MAGIC, 4) != 0) {
    fprintf(stderr, "memcmp of the ELF magic bytes failed\n");
    return EXIT_FAILURE;
  }

  return 0;
}
