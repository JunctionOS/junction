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
  setvbuf(stdout, NULL, _IONBF, 0);  // make stdout unbuffered
  printf("Hello, world!\n");

  // Leave a pipe open for testing
  int pipe_fds[2];
  if (pipe(pipe_fds) == -1) {
    perror("pipe");
    return EXIT_FAILURE;
  }
  printf("pipe rx fd: %d\n", pipe_fds[0]);
  printf("pipe tx fd: %d\n", pipe_fds[1]);

  int linux_fd = open(argv[0], O_RDONLY, 0644);
  if (linux_fd == -1) {
    perror("linuxfd open");
    return EXIT_FAILURE;
  }
  printf("linux fd: %d\n", linux_fd);

  if (write(pipe_fds[1], "TEST", 4) == -1) {
    perror("write");
    return EXIT_FAILURE;
  }
  printf("write succeeded\n");

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");
  char linux_fd_chars[4] = {0};
  ssize_t linux_rd_ret = read(linux_fd, &linux_fd_chars, 4);
  if (linux_rd_ret == -1) {
    perror("linux read");
    return EXIT_FAILURE;
  } else if (linux_rd_ret != 4) {
    fprintf(stderr, "failed to read the 4 bytes from the linux file");
    return EXIT_FAILURE;
  }
  printf("read %c%c%c%c [%hhx %hhx %hhx %hhx] from %s: %zd\n",
         linux_fd_chars[0], linux_fd_chars[1], linux_fd_chars[2],
         linux_fd_chars[3], linux_fd_chars[0], linux_fd_chars[1],
         linux_fd_chars[2], linux_fd_chars[3], argv[0], linux_rd_ret);

  if (memcmp(linux_fd_chars, ELF_MAGIC, 4) != 0) {
    fprintf(stderr, "memcmp of the ELF magic bytes failed\n");
    return EXIT_FAILURE;
  }

  char pipe_read_buf[4] = {0};
  ssize_t pipe_rd_ret = read(pipe_fds[0], pipe_read_buf, 4);
  if (pipe_rd_ret == -1) {
    perror("pipe read");
    return EXIT_FAILURE;
  } else if (pipe_rd_ret != 4) {
    fprintf(stderr, "failed to read 4 bytes from the pipe");
    return EXIT_FAILURE;
  }
  printf("read '%.*s' from pipe: %zd\n", 4, pipe_read_buf, pipe_rd_ret);

  return 0;
}
