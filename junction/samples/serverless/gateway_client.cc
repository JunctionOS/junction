#include "gateway_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

constexpr int GATEWAY_PORT = 8080;
constexpr const char *GATEWAY_IP = "10.10.1.1";
constexpr int RES_BUF_SIZE = 1024;

/**
 * @brief Call the gateway from a function when there is a function-to-function
 * invocation.
 *
 * @param req
 * @return response
 */
std::string CallGateway(const std::string &req) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    std::cerr << "Failed to create socket with gateway\n";
    return "Failed";
  }

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(GATEWAY_PORT);
  if (inet_pton(AF_INET, GATEWAY_IP, &addr.sin_addr) <= 0) {
    std::cerr << "Failed to set gateway IP address\n";
    close(fd);
    return "Failed";
  }

  if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    std::cerr << "Failed to connect to gateway\n";
    close(fd);
    return "Failed";
  }

  if (write(fd, req.c_str(), req.length()) != req.length()) {
    std::cerr << "Failed to write request to gateway\n";
    return "Failed";
  }

  char res[RES_BUF_SIZE];
  ssize_t n = read(fd, res, RES_BUF_SIZE - 1);
  if (n < 0) {
    std::cerr << "Failed to read response from gateway\n";
    return "Failed";
  }
  res[n] = '\0';
  return res;
}
