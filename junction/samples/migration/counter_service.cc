// counter_service.cc - stateful counter microservice for migration testing.
//
// Listens on a TCP port, accepts connections, and responds to simple commands:
//   "GET\n"       -> returns "COUNT <n>\n"
//   "INC\n"       -> increments counter, returns "OK\n"
//
// Usage: counter_service <port>
//
// To snapshot: send SIGSTOP (or use junction's snapshot mechanism).
// After restore, the counter value is preserved.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int counter = 0;

static void handle_client(int fd) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  long long us = (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  if (n <= 0) return;
  buf[n] = '\0';

  char resp[64];
  if (strncmp(buf, "INC", 3) == 0) {
    counter++;
    snprintf(resp, sizeof(resp), "OK\n");
  } else if (strncmp(buf, "GET", 3) == 0) {
    snprintf(resp, sizeof(resp), "COUNT %d\n", counter);
  } else {
    snprintf(resp, sizeof(resp), "ERR\n");
  }
  fprintf(stdout, "request '%.*s' at %lld us\n", (int)(n - 1), buf, us);
  fflush(stdout);
  write(fd, resp, strlen(resp));
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    return EXIT_FAILURE;
  }

  int port = atoi(argv[1]);
  int srv = socket(AF_INET, SOCK_STREAM, 0);
  int opt = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  bind(srv, (struct sockaddr *)&addr, sizeof(addr));
  listen(srv, 16);

  fprintf(stdout, "counter_service listening on port %d\n", port);
  fflush(stdout);

  while (1) {
    int fd = accept(srv, nullptr, nullptr);
    if (fd < 0) continue;
    handle_client(fd);
    close(fd);
  }
}
