#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <vector>

constexpr int FUNCTION_PORT = 43;
constexpr const char *FUNCTION_IP = "10.10.1.3";

namespace {

int fd = -1;

bool ConnectToServer() {
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    std::cerr << "Failed to create socket\n";
    return false;
  }

  sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(FUNCTION_PORT);
  if (inet_pton(AF_INET, FUNCTION_IP, &server_addr.sin_addr) <= 0) {
    std::cerr << "Failed to set server IP address\n";
    return false;
  }

  std::cout << std::unitbuf << "Connecting to " << FUNCTION_IP << ":"
            << FUNCTION_PORT << "...\n";
  if (connect(fd, reinterpret_cast<sockaddr *>(&server_addr),
              sizeof(server_addr)) < 0) {
    std::cerr << "Failed to connect to server\n";
    return false;
  }
  return true;
}

void CloseConnection() { close(fd); }

bool WriteRequest(const std::string &req) {
  std::cout << std::unitbuf << "Sending: " << req << "\n";
  const char *data = req.c_str();
  uint64_t len = req.length();

  if (write(fd, &len, sizeof(len)) != sizeof(len)) {
    std::cerr << "Failed to write length header\n";
    return false;
  }

  if (write(fd, data, len) != len) {
    std::cerr << "Failed to write data\n";
    return false;
  }
  return true;
}

bool ReadResponse(std::string &res) {
  uint64_t len = 0;
  if (read(fd, &len, sizeof(len)) != sizeof(len)) {
    std::cerr << "Failed to read response length\n";
    return false;
  }

  if (len == 0) { return true; }

  std::vector<char> buffer(len);
  if (read(fd, buffer.data(), len) != len) {
    std::cerr << "Failed to read response data\n";
    return false;
  }

  res = std::string(buffer.data(), len);
  std::cout << std::unitbuf << "Server Response: " << res << "\n";
  return true;
}

}  // namespace

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: ./client \"Your request string\"\n";
    return 1;
  }
  std::string req = argv[1];

  if (!ConnectToServer()) { return 1; }

  if (!WriteRequest(req)) { return 1; }

  std::string res;
  if (!ReadResponse(res)) { return 1; }

  CloseConnection();
  return 0;
}
