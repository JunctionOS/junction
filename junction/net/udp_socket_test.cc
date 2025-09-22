// Comprehensive UDP socket tests covering different bind addresses,
// syscall combinations, and socket configurations

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

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <vector>

const int TEST_PORT_BASE = 8000;
const int MESSAGE_SIZE = 64;
const int TEST_MESSAGES = 10;

// Test configuration structure
struct TestConfig {
  std::string bind_addr;
  std::string target_addr;
  int port;
  bool use_connected_socket;
  bool bind_socket;
  std::string test_name;
};

std::string DiscoverSpecificIP() {
  int sock;
  struct sockaddr_in serv, name;
  socklen_t namelen = sizeof(name);

  // Create UDP socket
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    exit(1);
  }

  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_port = htons(53);                      // DNS port
  inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);  // Google's DNS

  // "Connect" (no packets actually sent yet)
  if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
    perror("connect");
    close(sock);
    exit(1);
  }

  // Get local address
  if (getsockname(sock, (struct sockaddr*)&name, &namelen) == -1) {
    perror("getsockname");
    close(sock);
    exit(1);
  }

  char ip[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &name.sin_addr, ip, sizeof(ip)) == NULL) {
    perror("inet_ntop");
    close(sock);
    exit(1);
  }

  close(sock);
  return ip;
}

class UDPSocketTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Get the custom IP address from environment or use default
    custom_ip_ = DiscoverSpecificIP();
  }

  std::string custom_ip_;
  int port_counter_ = TEST_PORT_BASE;

  int GetNextPort() { return port_counter_++; }

  // Helper function to create and bind a socket
  int CreateBoundSocket(const std::string& bind_addr, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      return -1;
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      close(fd);
      return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr) != 1) {
      close(fd);
      return -1;
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
      close(fd);
      return -1;
    }

    return fd;
  }

  // Helper function to create a connected socket
  int CreateConnectedSocket(const std::string& target_addr, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, target_addr.c_str(), &addr.sin_addr) != 1) {
      close(fd);
      return -1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
      close(fd);
      return -1;
    }

    return fd;
  }

  // Test sendto/recvfrom combination
  void TestSendtoRecvfrom(const TestConfig& config) {
    int server_fd = -1, client_fd = -1;

    // Create server socket
    if (config.bind_socket) {
      server_fd = CreateBoundSocket(config.bind_addr, config.port);
      ASSERT_NE(server_fd, -1) << "Failed to create bound server socket";
    } else {
      server_fd = socket(AF_INET, SOCK_DGRAM, 0);
      ASSERT_NE(server_fd, -1) << "Failed to create server socket";
    }

    // Create client socket
    if (config.use_connected_socket) {
      client_fd = CreateConnectedSocket(config.target_addr, config.port);
      ASSERT_NE(client_fd, -1) << "Failed to create connected client socket";
    } else {
      client_fd = socket(AF_INET, SOCK_DGRAM, 0);
      ASSERT_NE(client_fd, -1) << "Failed to create client socket";
    }

    // Test communication
    char send_buf[MESSAGE_SIZE];
    char recv_buf[MESSAGE_SIZE];
    memset(send_buf, 'A', MESSAGE_SIZE);
    memset(recv_buf, 0, MESSAGE_SIZE);

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config.port);
    // check for er
    if (inet_pton(AF_INET, config.target_addr.c_str(), &target_addr.sin_addr) !=
        1) {
      ASSERT_TRUE(false) << "Invalid target address: " << config.target_addr;
    }

    for (int i = 0; i < TEST_MESSAGES; i++) {
      // Send from client
      ssize_t sent = 0;
      if (config.use_connected_socket) {
        sent = send(client_fd, send_buf, MESSAGE_SIZE, 0);
      } else {
        sent = sendto(client_fd, send_buf, MESSAGE_SIZE, 0,
                      (struct sockaddr*)&target_addr, sizeof(target_addr));
      }
      EXPECT_EQ(sent, MESSAGE_SIZE) << "Send failed on iteration " << i;

      // Receive on server
      struct sockaddr_in from_addr;
      socklen_t from_len = sizeof(from_addr);
      ssize_t received = recvfrom(server_fd, recv_buf, MESSAGE_SIZE, 0,
                                  (struct sockaddr*)&from_addr, &from_len);
      EXPECT_EQ(received, MESSAGE_SIZE) << "Recvfrom failed on iteration " << i;

      // Verify data
      EXPECT_EQ(memcmp(send_buf, recv_buf, MESSAGE_SIZE), 0)
          << "Data mismatch on iteration " << i;

      // Send response back
      ssize_t response_sent = sendto(server_fd, recv_buf, MESSAGE_SIZE, 0,
                                     (struct sockaddr*)&from_addr, from_len);
      EXPECT_EQ(response_sent, MESSAGE_SIZE)
          << "Response send failed on iteration " << i;

      // Receive response on client
      ssize_t response_received = 0;
      if (config.use_connected_socket) {
        response_received = recv(client_fd, recv_buf, MESSAGE_SIZE, 0);
      } else {
        response_received =
            recvfrom(client_fd, recv_buf, MESSAGE_SIZE, 0, NULL, NULL);
      }
      EXPECT_EQ(response_received, MESSAGE_SIZE)
          << "Response recv failed on iteration " << i;
    }

    close(server_fd);
    close(client_fd);
  }

  // Test send/recv combination (for connected sockets)
  void TestSendRecv(const TestConfig& config) {
    ASSERT_TRUE(config.use_connected_socket)
        << "TestSendRecv requires connected socket";

    int server_fd = -1, client_fd = -1;

    // Create server socket
    if (config.bind_socket) {
      server_fd = CreateBoundSocket(config.bind_addr, config.port);
      ASSERT_NE(server_fd, -1) << "Failed to create bound server socket";
    } else {
      server_fd = socket(AF_INET, SOCK_DGRAM, 0);
      ASSERT_NE(server_fd, -1) << "Failed to create server socket";
    }

    // Create connected client socket
    client_fd = CreateConnectedSocket(config.target_addr, config.port);
    ASSERT_NE(client_fd, -1) << "Failed to create connected client socket";

    char send_buf[MESSAGE_SIZE];
    char recv_buf[MESSAGE_SIZE];
    memset(send_buf, 'B', MESSAGE_SIZE);
    memset(recv_buf, 0, MESSAGE_SIZE);

    for (int i = 0; i < TEST_MESSAGES; i++) {
      // Send from client
      ssize_t sent = send(client_fd, send_buf, MESSAGE_SIZE, 0);
      EXPECT_EQ(sent, MESSAGE_SIZE) << "Send failed on iteration " << i;

      // Receive on server
      struct sockaddr_in from_addr;
      socklen_t from_len = sizeof(from_addr);
      ssize_t received = recvfrom(server_fd, recv_buf, MESSAGE_SIZE, 0,
                                  (struct sockaddr*)&from_addr, &from_len);
      EXPECT_EQ(received, MESSAGE_SIZE) << "Recvfrom failed on iteration " << i;

      // Verify data
      EXPECT_EQ(memcmp(send_buf, recv_buf, MESSAGE_SIZE), 0)
          << "Data mismatch on iteration " << i;
    }

    close(server_fd);
    close(client_fd);
  }

  // Test address isolation - ensure 127.0.0.1 doesn't receive 192.168.127.7
  // traffic
  void TestAddressIsolation() {
    int localhost_fd = CreateBoundSocket("127.0.0.1", GetNextPort());
    ASSERT_NE(localhost_fd, -1) << "Failed to create localhost socket";

    int custom_fd = CreateBoundSocket(custom_ip_, GetNextPort());
    ASSERT_NE(custom_fd, -1) << "Failed to create custom IP socket";

    char send_buf[MESSAGE_SIZE];
    memset(send_buf, 'C', MESSAGE_SIZE);

    // Send to custom IP from localhost
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(GetNextPort());
    inet_pton(AF_INET, custom_ip_.c_str(), &target_addr.sin_addr);

    ssize_t sent = sendto(localhost_fd, send_buf, MESSAGE_SIZE, 0,
                          (struct sockaddr*)&target_addr, sizeof(target_addr));
    EXPECT_EQ(sent, MESSAGE_SIZE) << "Failed to send to custom IP";

    // Try to receive on localhost socket - should timeout or fail
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(localhost_fd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int result = select(localhost_fd + 1, &readfds, NULL, NULL, &timeout);
    EXPECT_EQ(result, 0)
        << "Localhost socket should not receive custom IP traffic";

    close(localhost_fd);
    close(custom_fd);
  }
};

// Test cases for different bind addresses
TEST_F(UDPSocketTest, BindAnyAddress_SendtoRecvfrom) {
  TestConfig config = {"0.0.0.0", "127.0.0.1", GetNextPort(),
                       false,     true,        "BindAny_SendtoRecvfrom"};
  TestSendtoRecvfrom(config);
}

TEST_F(UDPSocketTest, BindLocalhost_SendtoRecvfrom) {
  TestConfig config = {"127.0.0.1",   "127.0.0.1",
                       GetNextPort(), false,
                       true,          "BindLocalhost_SendtoRecvfrom"};
  TestSendtoRecvfrom(config);
}

TEST_F(UDPSocketTest, BindCustomIP_SendtoRecvfrom) {
  TestConfig config = {custom_ip_, custom_ip_, GetNextPort(),
                       false,      true,       "BindCustomIP_SendtoRecvfrom"};
  TestSendtoRecvfrom(config);
}

// Test cases for connected sockets
TEST_F(UDPSocketTest, ConnectedSocket_SendRecv) {
  TestConfig config = {"127.0.0.1", "127.0.0.1", GetNextPort(),
                       true,        true,        "Connected_SendRecv"};
  TestSendRecv(config);
}

TEST_F(UDPSocketTest, ConnectedSocket_SendtoRecvfrom) {
  TestConfig config = {"127.0.0.1", "127.0.0.1", GetNextPort(),
                       true,        true,        "Connected_SendtoRecvfrom"};
  TestSendtoRecvfrom(config);
}

// Test cases for different address combinations
TEST_F(UDPSocketTest, BindAnyToSpecifiedIP) {
  TestConfig config = {"0.0.0.0", custom_ip_, GetNextPort(),
                       false,     true,       "BindAnyToSpecifiedIP"};
  TestSendtoRecvfrom(config);
}

// Test address isolation
TEST_F(UDPSocketTest, AddressIsolation) { TestAddressIsolation(); }

// Test with different syscall combinations
TEST_F(UDPSocketTest, MixedSyscalls_ConnectedSocket) {
  int portno = GetNextPort();
  int server_fd = CreateBoundSocket("127.0.0.1", portno);
  ASSERT_NE(server_fd, -1) << "Failed to create server socket";

  int client_fd = CreateConnectedSocket("127.0.0.1", portno);
  ASSERT_NE(client_fd, -1) << "Failed to create client socket";

  char send_buf[MESSAGE_SIZE];
  char recv_buf[MESSAGE_SIZE];
  memset(send_buf, 'D', MESSAGE_SIZE);

  // Mix send/sendto and recv/recvfrom
  for (int i = 0; i < TEST_MESSAGES; i++) {
    ssize_t sent = 0;
    if (i % 2 == 0) {
      sent = send(client_fd, send_buf, MESSAGE_SIZE, 0);
    } else {
      struct sockaddr_in target_addr;
      memset(&target_addr, 0, sizeof(target_addr));
      target_addr.sin_family = AF_INET;
      target_addr.sin_port = htons(portno);
      inet_pton(AF_INET, "127.0.0.1", &target_addr.sin_addr);
      sent = sendto(client_fd, send_buf, MESSAGE_SIZE, 0,
                    (struct sockaddr*)&target_addr, sizeof(target_addr));
    }
    EXPECT_EQ(sent, MESSAGE_SIZE) << "Send failed on iteration " << i;

    // Always use recvfrom on server side
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t received = recvfrom(server_fd, recv_buf, MESSAGE_SIZE, 0,
                                (struct sockaddr*)&from_addr, &from_len);
    EXPECT_EQ(received, MESSAGE_SIZE) << "Recvfrom failed on iteration " << i;
  }

  close(server_fd);
  close(client_fd);
}

// Test with different port numbers
TEST_F(UDPSocketTest, DifferentPorts) {
  std::vector<int> ports = {8001, 8002, 8003, 8004, 8005};

  for (int port : ports) {
    TestConfig config = {"127.0.0.1", "127.0.0.1",
                         port,        false,
                         true,        "DifferentPort_" + std::to_string(port)};
    TestSendtoRecvfrom(config);
  }
}

// Test with large messages
TEST_F(UDPSocketTest, LargeMessage) {
  const int large_size = 1024;
  char send_buf[large_size];
  char recv_buf[large_size];
  memset(send_buf, 'E', large_size);
  int portno = GetNextPort();

  int server_fd = CreateBoundSocket("127.0.0.1", portno);
  ASSERT_NE(server_fd, -1) << "Failed to create server socket";

  int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_NE(client_fd, -1) << "Failed to create client socket";

  struct sockaddr_in target_addr;
  memset(&target_addr, 0, sizeof(target_addr));
  target_addr.sin_family = AF_INET;
  target_addr.sin_port = htons(portno);
  inet_pton(AF_INET, "127.0.0.1", &target_addr.sin_addr);

  ssize_t sent = sendto(client_fd, send_buf, large_size, 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
  EXPECT_EQ(sent, large_size) << "Failed to send large message";

  struct sockaddr_in from_addr;
  socklen_t from_len = sizeof(from_addr);
  ssize_t received = recvfrom(server_fd, recv_buf, large_size, 0,
                              (struct sockaddr*)&from_addr, &from_len);
  EXPECT_EQ(received, large_size) << "Failed to receive large message";

  EXPECT_EQ(memcmp(send_buf, recv_buf, large_size), 0)
      << "Large message data mismatch";

  close(server_fd);
  close(client_fd);
}
