// Source: https://github.com/detailyang/ipc_benchmark
// Note: With some modifications.

extern "C" {
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
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

int ReadFull(const int fd, unsigned char *buf, const int size) {
  ssize_t n = 0;

  pollfd pfd = {.fd = fd, .events = POLLIN};

  while (n < size) {
    int pret = poll(&pfd, 1, -1);
    assert(pret == 1);
    assert(pfd.revents == POLLIN);

    ssize_t ret = read(fd, (void *)(buf + n), size - n);
    if (ret == 0) {
      break;
    } else if (ret == -1) {
      perror("read");
      return -1;
    } else {
      n += ret;
    }
  }
  return n;
}

int main(int argc, char *argv[]) {
  int fd, nfd, yes;
  int size, count, sum, n;
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

  memset(&in, 0, sizeof(in));
  fd = socket(AF_INET, SOCK_STREAM, 0);
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
  }

  printf("Listening on IP: %s\n", str);

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

  if (listen(fd, 128) == -1) {
    perror("listen");
    close(fd);
    return 1;
  }

  if ((nfd = accept(fd, NULL, NULL)) == -1) {
    perror("accept");
    close(fd);
    return 1;
  }

  sum = 0;
  for (;;) {
    n = ReadFull(nfd, buf, size);
    if (n == 0) {
      break;
    } else if (n == -1) {
      perror("read");
      close(nfd);
      close(fd);
      return 1;
    }
    sum += n;
  }

  if (sum != count * size) {
    fprintf(stderr, "sum error: %d != %d\n", sum, count * size);
    close(nfd);
    close(fd);
    return 1;
  }

  close(nfd);
  close(fd);

  return 0;
}
