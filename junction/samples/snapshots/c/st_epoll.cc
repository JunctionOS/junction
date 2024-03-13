#include <sys/epoll.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define MAX_EVENTS (10)

int main(int argc, char *argv[]) {
  printf("Hello, world!\n");

  // Leave a pipe open for testing
  int pipe_fds[2];
  if (pipe(pipe_fds) == -1) {
    perror("pipe");
    return EXIT_FAILURE;
  }
  printf("pipe rx fd: %d\n", pipe_fds[0]);
  printf("pipe tx fd: %d\n", pipe_fds[1]);

  int epoll_fd = epoll_create(0);
  if (epoll_fd < 0) {
    perror("epoll_create");
    return EXIT_FAILURE;
  }
  printf("epoll fd: %d\n", epoll_fd);

  struct epoll_event ev = {EPOLLIN, {.fd = pipe_fds[0]}};
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_fds[0], &ev) != 0) {
    perror("epoll_ctl");
    return EXIT_FAILURE;
  }
  printf("epoll_ctl succeeded\n");

  if (write(pipe_fds[1], "TEST", 4) == -1) {
    perror("write");
    return EXIT_FAILURE;
  }

  printf("write succeeded\n");

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");

  bool running = true;
  while (running) {
    printf("Polling\n");
    struct epoll_event events[MAX_EVENTS];
    int event_count =
        epoll_wait(epoll_fd, events, MAX_EVENTS, 30000 /* timeout */);
    if (event_count < 0) {
      perror("epoll_wait");
      return EXIT_FAILURE;
    }

    printf("%d ready events\n", event_count);
    for (int i = 0; i < event_count; i++) {
      printf("reading from fd %d\n", events[i].data.fd);
      char pipe_read_buf[4] = {0};
      ssize_t pipe_rd_ret = read(events[i].data.fd, pipe_read_buf, 4);
      if (pipe_rd_ret == -1) {
        perror("pipe read");
        return EXIT_FAILURE;
      } else if (pipe_rd_ret != 4) {
        fprintf(stderr, "failed to read 4 bytes from the pipe");
        return EXIT_FAILURE;
      }
      printf("read '%.*s' from pipe: %zd\n", 4, pipe_read_buf, pipe_rd_ret);
      running = false;
    }
  }

  close(pipe_fds[0]);
  close(pipe_fds[1]);
  return 0;
}
