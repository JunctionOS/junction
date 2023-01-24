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

#include <chrono>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

using namespace std::chrono;
using sec = duration<double>;

constexpr uint16_t kNetperfPort = 8080;
constexpr uint64_t kNetperfMagic = 0xF00BAD11DEADBEEF;
constexpr size_t kMaxBuffer = 0x10000000;

enum {
  kTCPStream = 0,
  kTCPRR,
};

struct server_init_msg {
  uint64_t magic;
  uint64_t mode;
  size_t buflen;
};

int ReadFull(const int fd, char *buf, const int size) {
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

int WriteFull(const int fd, const char *buf, const int size) {
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

void ServerWorker(int c) {
  server_init_msg msg;
  ssize_t ret = ReadFull(c, reinterpret_cast<char *>(&msg), sizeof(msg));
  if (ret != static_cast<ssize_t>(sizeof(msg))) {
    if (ret == 0 || ret == -ECONNRESET) return;
    std::cerr << "read failed, ret = " << ret << std::endl;
    return;
  }

  if (msg.magic != kNetperfMagic) {
    std::cerr << "invalid magic " << msg.magic << std::endl;
    return;
  }

  bool write_back;
  switch (msg.mode) {
    case kTCPStream:
      write_back = false;
      break;
    case kTCPRR:
      write_back = true;
      break;
    default:
      std::cerr << "invalid mode " << msg.mode << std::endl;
      return;
  }

  size_t buflen = std::min(msg.buflen, kMaxBuffer);
  std::unique_ptr<char[]> buf(new char[buflen]);
  while (true) {
    ret = ReadFull(c, buf.get(), buflen);
    if (ret != static_cast<ssize_t>(buflen)) {
      if (ret == 0 || ret == -ECONNRESET) break;
      std::cerr << "read failed, ret = " << ret << std::endl;
      break;
    }
    if (write_back) {
      ret = WriteFull(c, buf.get(), buflen);
      if (ret != static_cast<ssize_t>(buflen)) {
        if (ret == -EPIPE || ret == -ECONNRESET) break;
        std::cerr << "write failed, ret = " << ret << std::endl;
        break;
      }
    }
  }
}

void RunServer() {
  int q = socket(AF_INET, SOCK_STREAM, 0);
  if (q == -1) {
    perror("socket");
    exit(1);
  }

  struct sockaddr_in in;
  memset(&in, 0, sizeof(in));
  in.sin_family = AF_INET;
  in.sin_port = htons(kNetperfPort);
  in.sin_addr.s_addr = 0;
  if (bind(q, (struct sockaddr *)&in, sizeof(in)) == -1) {
    perror("bind");
    close(q);
    exit(1);
  }

  if (listen(q, 4096 /* backlog */) == -1) {
    perror("listen");
    close(q);
    exit(1);
  }

  char str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(in.sin_addr), str, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    close(q);
  }

  std::cout << "Listening on IP: " << str << std::endl;

  while (true) {
    int c;
    if ((c = accept(q, NULL, NULL)) == -1) {
      perror("accept");
      close(q);
      exit(1);
    }
    std::thread([=] { ServerWorker(c); }).detach();
  }
}

int main(int argc, char *argv[]) {
  if (argc != 1) {
    std::cerr << "usage: ./netperf_server" << std::endl;
    return 1;
  }

  RunServer();

  return 0;
}
