#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <ios>
#include <iostream>
#include <thread>

constexpr int GATEWAY_PORT = 8080;
constexpr const char *FUNCTION_IP = "10.10.1.3";
constexpr int FUNCTION_PORT = 43;
constexpr int REQ_BUF_SIZE = 4096;

namespace {

int gw_fd;
sockaddr_in gw_addr;
int addrlen;
int func_fd;

bool InitGateway() {
  gw_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (gw_fd < 0) {
    std::cerr << "Failed to create socket\n";
    return false;
  }

  // int opt = 1;
  // if (setsockopt(gw_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
  //                sizeof(opt)) < 0) {
  //   std::cerr << "Failed to set socket options\n";
  //   return false;
  // }

  gw_addr.sin_family = AF_INET;
  gw_addr.sin_addr.s_addr = INADDR_ANY;
  gw_addr.sin_port = htons(GATEWAY_PORT);
  addrlen = sizeof(gw_addr);

  if (bind(gw_fd, reinterpret_cast<sockaddr *>(&gw_addr), addrlen) < 0) {
    std::cerr << "Failed to bind socket\n";
    return false;
  }

  if (listen(gw_fd, 3) < 0) {
    std::cerr << "Failed to listen\n";
    return false;
  }

  std::cout << std::unitbuf << "[Gateway] Listening on port " << GATEWAY_PORT
            << "\n";
  return true;
}

bool ConnectToFunctionServer() {
  func_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (func_fd < 0) {
    std::cerr << "Failed to create socket with function server\n";
    return false;
  }

  sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(FUNCTION_PORT);
  if (inet_pton(AF_INET, FUNCTION_IP, &server_addr.sin_addr) <= 0) {
    std::cerr << "Failed to set function server IP address\n";
    close(func_fd);
    return false;
  }

  std::cout << std::unitbuf << "[Gateway] Connecting to " << FUNCTION_IP << ":"
            << FUNCTION_PORT << "...\n";
  if (connect(func_fd, reinterpret_cast<sockaddr *>(&server_addr),
              sizeof(server_addr)) < 0) {
    std::cerr << "Failed to connect to function server\n";
    close(func_fd);
    return false;
  }

  std::cout << std::unitbuf << "[Gateway] Connected to " << FUNCTION_IP << ":"
            << FUNCTION_PORT << "\n";
  return true;
}

bool WriteRequestToFunc(const char *buf, ssize_t req_len) {
  if (write(func_fd, &req_len, sizeof(req_len)) != sizeof(req_len)) {
    std::cerr << "Failed to write length header\n";
    return false;
  }

  if (write(func_fd, buf, req_len) != req_len) {
    std::cerr << "Failed to write data\n";
    return false;
  }

  std::cout << std::unitbuf << "[Gateway] Wrote request to function server\n";
  return true;
}

ssize_t ReadResponseFromFunc(char *buf) {
  std::cout << std::unitbuf
            << "[Gateway] Waiting for response from function server...\n";
  ssize_t len = 0;
  if (read(func_fd, &len, sizeof(len)) != sizeof(len)) {
    std::cerr << "Failed to read response lenght\n";
    return -1;
  }

  if (len == 0) { return 0; }
  if (read(func_fd, buf, len) != len) {
    std::cerr << "Failed to read response data\n";
    return -1;
  }
  return len;
}

ssize_t ReadRequestFromClient(int client_fd, char *buf) {
  std::cout << std::unitbuf << "[Gateway] Waiting for request from client...\n";
  ssize_t n = read(client_fd, buf, REQ_BUF_SIZE - 1);
  if (n <= 0) {
    std::cerr << "Failed to read request from client\n";
    close(client_fd);
    return -1;
  }
  buf[n] = '\0';
  // strip new line character at end
  if (buf[n - 1] == '\n') {
    buf[n - 1] = '\0';
    n--;
  }

  std::cout << std::unitbuf << "[Gateway] Received: " << buf << " (" << n
            << " bytes) from client.\n";
  return n;
}

bool WriteResponseToClient(int client_fd, const char *buf, ssize_t res_len) {
  if (write(client_fd, buf, res_len) < 0) {
    std::cerr << "[Gateway] Failed to write back to client\n";
    return false;
  }
  std::cout << std::unitbuf << "[Gateway] Forwarded response to client.\n";
  return true;
}

void ProcessRequest(int client_fd) {
  char buffer[REQ_BUF_SIZE];
  ssize_t req_len = ReadRequestFromClient(client_fd, buffer);
  if (req_len < 0) {
    close(client_fd);
    return;
  }

  if (!ConnectToFunctionServer()) {
    close(client_fd);
    return;
  }

  if (!WriteRequestToFunc(buffer, req_len)) {
    close(func_fd);
    close(client_fd);
    return;
  }
  ssize_t res_len = ReadResponseFromFunc(buffer);
  if (res_len < 0) {
    close(func_fd);
    close(client_fd);
    return;
  }

  if (!WriteResponseToClient(client_fd, buffer, res_len)) {}

  close(func_fd);
  close(client_fd);
}

void HandleRequest() {
  while (true) {
    int new_socket = accept(gw_fd, reinterpret_cast<sockaddr *>(&gw_addr),
                            reinterpret_cast<socklen_t *>(&addrlen));
    if (new_socket < 0) {
      std::cerr << "Failed to accept new socket\n";
      continue;
    }

    // TODO: mutex for fd
    std::thread(ProcessRequest, new_socket).detach();
  }
}
}  // namespace

int main() {
  if (!InitGateway()) { return 1; }

  HandleRequest();

  return 0;
}
