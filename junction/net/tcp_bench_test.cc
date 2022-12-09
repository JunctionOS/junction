// Source: https://github.com/detailyang/ipc_benchmark
// Note: With some modifications to make it run with threads and as a gtest.

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

#include <thread>
#include <future>
#include <gtest/gtest.h>

const int SIZE = 4096;
const int COUNT = 10000;

const char IP[] = "127.0.0.1";
const int PORT = 2227;

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

int ReadFull(const int fd, unsigned char *buf, const int size) {
  ssize_t n = 0;
  while (n < size) {
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

int Server() {
  int fd, nfd, yes;
  int sum, n;
  unsigned char *buf;
  struct sockaddr_in in;

  buf = (unsigned char *)malloc(SIZE);
  if (buf == NULL) {
    fprintf(stderr, "Cannot allocate buffer\n");
    return 1;
  }

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
    return 1;
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
    n = ReadFull(nfd, buf, SIZE);
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

  if (sum != COUNT * SIZE) {
    fprintf(stderr, "sum error: %d != %d\n", sum, COUNT * SIZE);
    close(nfd);
    close(fd);
    return 1;
  }

  close(nfd);
  close(fd);

  return 0;
}

int Client() {
  int fd, i;
  unsigned char *buf;
  struct timeval begin, end;
  struct sockaddr_in in;

  buf = (unsigned char *)malloc(SIZE);

  memset(&in, 0, sizeof(in));
  sleep(1);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == -1) {
    perror("socket");
    return 1;
  }

  in.sin_family = AF_INET;
  in.sin_port = htons(PORT);
  if (inet_pton(AF_INET, IP, &in.sin_addr) != 1) {
    close(fd);
    return 1;
  }

  char str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(in.sin_addr), str, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    close(fd);
    return 1;
  }

  printf("Connecting to IP: %s\n", str);

  if (connect(fd, (struct sockaddr *)&in, sizeof(in)) == -1) {
    perror("connect");
    close(fd);
    return 1;
  }

  gettimeofday(&begin, NULL);

  for (i = 0; i < COUNT; i++) {
    if (WriteFull(fd, buf, SIZE) == -1) {
      close(fd);
      return 1;
    }
  }

  gettimeofday(&end, NULL);

  double tm = GetElapsed(&begin, &end);
  printf("%.0fMB/s %.0fmsg/s\n", COUNT * SIZE * 1.0 / (tm * 1024 * 1024),
         COUNT * 1.0 / tm);

  close(fd);

  return 0;
}

class TCPTest : public ::testing::Test {};

TEST_F(TCPTest, ReadWrite) {
  printf("TCP (size: %d, count: %d)\n", SIZE, COUNT);

  auto server = std::async(std::launch::async, Server);
  auto client = std::async(std::launch::async, Client);
  EXPECT_EQ(0, server.get());
  EXPECT_EQ(0, client.get());
}
