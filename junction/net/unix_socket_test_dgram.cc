#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

// Define the socket path
#define SOCKET_PATH "/tmp/unix_dgram_socket"

int server_sock;

void server() {
  server_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (server_sock < 0) {
    perror("Server socket creation failed");
    return;
  }

  struct sockaddr_un server_addr {};
  server_addr.sun_family = AF_UNIX;
  strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

  unlink(SOCKET_PATH);  // Ensure the socket path is free
  if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("Server bind failed");
    close(server_sock);
    return;
  }

  char buffer[1024];
  struct sockaddr_un client_addr {};
  socklen_t client_len = sizeof(client_addr);

  while (true) {
    memset(buffer, 0, sizeof(buffer));

    ssize_t len = recvfrom(server_sock, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&client_addr, &client_len);
    if (len == 0) break;
    if (len < 0) {
      perror("Server recvfrom failed");
      break;
    }

    std::cout << "Server received: " << buffer << std::endl;

    // Echo back the received message
    if (sendto(server_sock, buffer, len, 0, (struct sockaddr *)&client_addr,
               client_len) < 0) {
      perror("Server sendto failed");
      break;
    }
  }

  close(server_sock);
  unlink(SOCKET_PATH);
}

void client() {
  int client_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (client_sock < 0) {
    perror("Client socket creation failed");
    return;
  }

  // Client socket (optional bind)
  struct sockaddr_un client_addr {};
  client_addr.sun_family = AF_UNIX;
  strncpy(client_addr.sun_path, "/tmp/unix_dgram_client_socket",
          sizeof(client_addr.sun_path) - 1);

  // Optional binding
  unlink(client_addr.sun_path);  // Ensure the socket path is free
  if (bind(client_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) <
      0) {
    perror("Client bind failed");
    close(client_sock);
    return;
  }

  // Server address
  struct sockaddr_un server_addr {};
  server_addr.sun_family = AF_UNIX;
  strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

  const char *messages[] = {"Message 1", "Message 2", "Message 3"};
  for (const auto &msg : messages) {
    // Test sendto
    if (sendto(client_sock, msg, strlen(msg), 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      perror("Client sendto failed");
    }

    // Test recvfrom
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t len =
        recvfrom(client_sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (len < 0) {
      perror("Client recvfrom failed");
    } else {
      std::cout << "Client received: " << buffer << std::endl;
    }

    if (std::string(msg) != std::string(buffer)) {
      std::cout << "expected " << msg << std::endl;
      exit(-1);
    }
  }

  close(client_sock);
  unlink(client_addr.sun_path);
  shutdown(server_sock, SHUT_RDWR);
}

int main() {
  std::thread server_thread(server);

  // Give the server time to start
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  std::thread client_thread(client);

  client_thread.join();
  server_thread.join();

  return 0;
}