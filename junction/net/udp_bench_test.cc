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

#include <gtest/gtest.h>

#include <future>
#include <thread>

const int SIZE = 1024;
const int COUNT = 5000;

const char IP[] = "127.0.0.1";
const int PORT = 2237;

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

int Server() {
  int fd, yes;
  int i, sum, n;
  unsigned char *buf;
  struct sockaddr_in in;

  buf = (unsigned char *)malloc(SIZE);
  if (buf == NULL) {
    fprintf(stderr, "Cannot allocate buffer\n");
    return 1;
  }

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
  for (i = 0; i < COUNT; i++) {
    n = Receive(fd, buf, SIZE);
    sum += n;
    if (n == SIZE) received++;
  }

  printf("Received %d messages\n", received);

  if (sum != COUNT * SIZE) {
    fprintf(stderr, "sum error: %d != %d\n", sum, COUNT * SIZE);
    close(fd);
    return 1;
  }

  close(fd);

  return 0;
}

int Client() {
  int fd, i;
  unsigned char *buf;
  struct timeval begin, end;
  struct sockaddr_in in;

  buf = (unsigned char *)malloc(SIZE);
  if (buf == NULL) {
    fprintf(stderr, "Cannot allocate buffer\n");
    return 1;
  }

  memset(&in, 0, sizeof(in));
  sleep(1);

  fd = socket(AF_INET, SOCK_DGRAM, 0);
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

  printf("Sending to IP: %s\n", str);

  gettimeofday(&begin, NULL);

  auto sent = 0;
  for (i = 0; i < COUNT; i++) {
    auto n = Send(fd, buf, SIZE, (struct sockaddr *)&in, sizeof(in));
    // Count only messages that were fully sent
    if (n == SIZE) sent++;
  }

  gettimeofday(&end, NULL);

  printf("Sent %d messages\n", sent);

  double tm = GetElapsed(&begin, &end);
  printf("%.0fMB/s %.0fmsg/s\n", sent * SIZE * 1.0 / (tm * 1024 * 1024),
         sent * 1.0 / tm);

  close(fd);

  return 0;
}

class UDPTest : public ::testing::Test {};

TEST_F(UDPTest, ReadWrite) {
  printf("UDP (size: %d, count: %d)\n", SIZE, COUNT);

  auto server = std::async(std::launch::async, Server);
  auto client = std::async(std::launch::async, Client);
  EXPECT_EQ(0, server.get());
  EXPECT_EQ(0, client.get());
}
