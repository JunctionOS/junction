// Source: https://github.com/detailyang/ipc_benchmark
// Note: With some modifications.

extern "C" {
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
}

const int PORT = 15000;

int Receive(const int fd, unsigned char *buf, const int size) {
  ssize_t n = 0;
  constexpr int flags = 0;
  while (n < size) {
    const auto len = size - n;
    ssize_t ret = recv(fd, (void *)(buf + n), len, flags);
    if (ret != len) {
      if (ret == 0) break;
      perror("recv");
      return -1;
    } else {
      n += ret;
    }
  }
  return n;
}

int main(int argc, char *argv[]) {
  int fd, yes;
  int i, size, count, sum, n;
  unsigned char *buf;
  struct sockaddr_in in;

  if (argc != 3) {
    printf("usage: ./server <size> <count>>\n");
    return 1;
  }

  size = atoi(argv[1]);
  count = atoi(argv[2]);

  buf = (unsigned char *)malloc(size);
  if (buf == NULL) {
    fprintf(stderr, "Cannot allocate buffer\n");
    return 1;
  }

  printf("Server (size: %d, count: %d)\n", size, count);

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    return 1;
  }

  in.sin_family = AF_INET;
  in.sin_port = htons(PORT);
  in.sin_addr.s_addr = 0;

  char str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(in.sin_addr), str, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    close(fd);
    return 1;
  }

  printf("Waiting on IP: %s\n", str);

  yes = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) {
    perror("setsockopt");
    close(fd);
    return 1;
  }

  if (bind(fd, (struct sockaddr *)&in, sizeof(in)) == -1) {
    perror("bind");
    close(fd);
    return 1;
  }

  sum = 0;
  auto received = 0;
  for (i = 0; i < count; i++) {
    n = Receive(fd, buf, size);
    sum += n;
    if (n == size) received++;
  }

  printf("Received %d messages\n", received);

  if (sum != count * size) {
    fprintf(stderr, "sum error: %d != %d\n", sum, count * size);
    close(fd);
    return 1;
  }

  close(fd);

  return 0;
}
