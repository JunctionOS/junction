#include <sys/socket.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0); // make stdout unbuffered

  // Leave a pipe open for testing
  int pipe_fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe_fds) == -1) {
    perror("socketpair");
    return EXIT_FAILURE;
  }
  printf("pipe rx fd: %d\n", pipe_fds[0]);
  printf("pipe tx fd: %d\n", pipe_fds[1]);

  if (write(pipe_fds[1], "TEST", 4) == -1) {
    perror("write");
    return EXIT_FAILURE;
  }
  printf("pipe write write succeeded\n");

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");

  char pipe_read_buf[4] = {0};
  ssize_t pipe_rd_ret = read(pipe_fds[0], pipe_read_buf, 4);
  if (pipe_rd_ret == -1) {
    perror("pipe read");
    return EXIT_FAILURE;
  } else if (pipe_rd_ret != 4) {
    fprintf(stderr, "failed to read 4 bytes from the pipe\n");
    return EXIT_FAILURE;
  }
  printf("read '%.*s' from pipe: %zd\n", 4, pipe_read_buf, pipe_rd_ret);

  if (memcmp(pipe_read_buf, "TEST", 4) != 0) {
    fprintf(stderr, "pipe read wrong data (should be TEST)\n");
    return EXIT_FAILURE;
  }

  return 0;
}
