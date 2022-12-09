extern "C" {
#include <arpa/inet.h>
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

double GetElapsed(struct timeval *begin, struct timeval *end) {
  return (end->tv_sec + end->tv_usec * 1.0 / 1000000) -
         (begin->tv_sec + begin->tv_usec * 1.0 / 1000000);
}

int WriteFull(const int fd, const unsigned char *buf, const int size) {
  ssize_t n = 0;
  while (n < size) {
    ssize_t ret = write(fd, buf + n, size - n);
    if (ret == 0) {
      break;
    } else if (ret == -1) {
      perror("write");
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

  printf("Client (size: %d, count: %d)\n", size, count);

  memset(&in, 0, sizeof(in));
  sleep(1);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
  }

  printf("Connecting to IP: %s\n", str);

  if (connect(fd, (struct sockaddr *)&in, sizeof(in)) == -1) {
    perror("connect");
    close(fd);
    return 1;
  }

  gettimeofday(&begin, NULL);

  for (i = 0; i < count; i++) {
    if (WriteFull(fd, buf, size) == -1) {
      close(fd);
      return 1;
    }
  }

  gettimeofday(&end, NULL);

  double tm = GetElapsed(&begin, &end);
  printf("%.0fMB/s %.0fmsg/s\n", count * size * 1.0 / (tm * 1024 * 1024),
         count * 1.0 / tm);

  close(fd);

  return 0;
}
