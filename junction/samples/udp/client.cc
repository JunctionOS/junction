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

#include <csignal>

const int PORT = 15000;

double GetElapsed(struct timeval *begin, struct timeval *end) {
  return (end->tv_sec + end->tv_usec * 1.0 / 1000000) -
         (begin->tv_sec + begin->tv_usec * 1.0 / 1000000);
}

int Send(const int fd, const unsigned char *buf, const int size,
         const struct sockaddr *dest_addr, const socklen_t addrlen) {
  ssize_t n = 0;
  constexpr int flags = 0;
  while (n < size) {
    const auto len = size - n;
    ssize_t ret = sendto(fd, buf + n, len, flags, dest_addr, addrlen);
    if (ret != len) {
      if (ret == -EPIPE) break;
      perror("sendto");
      return -1;
    } else {
      n += ret;
    }
  }
  return n;
}

int main(int argc, char *argv[]) {
  int fd;
  int i, size, count;
  unsigned char *buf;
  char *remote_ip;
  struct timeval begin, end;
  struct sockaddr_in in;

  if (argc != 4) {
    printf("usage: ./client <size> <count> <remote_ip>\n");
    return 1;
  }

  size = atoi(argv[1]);
  count = atoi(argv[2]);
  remote_ip = argv[3];

  buf = (unsigned char *)malloc(size);
  if (buf == NULL) {
    fprintf(stderr, "Cannot allocate buffer\n");
    return 1;
  }

  printf("Client (size: %d, count: %d)\n", size, count);

  memset(&in, 0, sizeof(in));
  sleep(1);

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    return 1;
  }

  in.sin_family = AF_INET;
  in.sin_port = htons(PORT);
  if (inet_pton(AF_INET, remote_ip, &in.sin_addr) != 1) {
    close(fd);
    return 1;
  }

  char str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(in.sin_addr), str, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    close(fd);
    return 1;
  }

  printf("Sending to IP: %s\n", str);

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  gettimeofday(&begin, NULL);

  auto sent = 0;
  for (i = 0; i < count; i++) {
    auto n = Send(fd, buf, size, (struct sockaddr *)&in, sizeof(in));
    // Count only messages that were fully sent
    if (n == size) sent++;
  }

  gettimeofday(&end, NULL);

  printf("Sent %d messages\n", sent);

  double tm = GetElapsed(&begin, &end);
  printf("%.0fMB/s %.0fmsg/s\n", sent * size * 1.0 / (tm * 1024 * 1024),
         sent * 1.0 / tm);

  close(fd);

  return 0;
}
