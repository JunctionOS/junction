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

int Server() {
  int fd, yes;
  int i;
  unsigned char buf[SIZE];
  struct sockaddr_in in;

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

  sockaddr_in recv;
  unsigned int socklen = sizeof(recv);
  for (i = 0; i < COUNT; i++) {
    ssize_t ret = recvfrom(fd, buf, SIZE, 0, (sockaddr *)&recv, &socklen);
    if (ret != SIZE) {
      perror("recvfrom");
      EXPECT_EQ(ret, SIZE);
    }

    ssize_t wret = sendto(fd, buf, SIZE, 0, (sockaddr *)&recv, sizeof(recv));
    if (wret != SIZE) {
      perror("sendto");
      EXPECT_EQ(wret, SIZE);
    }
  }

  printf("Ping ponged %d messages\n", COUNT);

  close(fd);

  return 0;
}

int Client() {
  int fd, i;
  unsigned char buf[SIZE];
  struct timeval begin, end;
  struct sockaddr_in in;

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

  for (i = 0; i < COUNT; i++) {
    ssize_t wret = sendto(fd, buf, SIZE, 0, (sockaddr *)&in, sizeof(in));
    if (wret != SIZE) {
      perror("wret");
      EXPECT_EQ(wret, SIZE);
    }

    ssize_t rret = recv(fd, buf, SIZE, 0);
    if (rret != SIZE) {
      perror("rret");
      EXPECT_EQ(rret, SIZE);
    }
  }

  gettimeofday(&end, NULL);

  double tm = GetElapsed(&begin, &end);
  printf("%.0fMB/s %.0fmsg/s\n", COUNT * SIZE * 1.0 / (tm * 1024 * 1024),
         COUNT * 1.0 / tm);

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
