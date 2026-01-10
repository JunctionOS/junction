#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdio>
#include <cstring>

constexpr const char *GATEWAY_IP = "10.10.1.1";
constexpr int GATEWAY_PORT = 8080;
constexpr const char *SIDECAR_IP = "127.0.0.1";
constexpr int SIDECAR_PORT = 9000;

using connect_func_t = int (*)(int, const struct sockaddr *, socklen_t);

extern "C" int connect(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {
  // get real connect function
  static connect_func_t real_connect = nullptr;
  if (!real_connect) {
    real_connect = (connect_func_t)dlsym(RTLD_NEXT, "connect");
    if (!real_connect) {
      fprintf(stderr,
              "[Shim] Critical Error: dlsym failed to find 'connect'\n");
      return -1;
    }
  }
  if (addr->sa_family == AF_INET) {
    const auto *addr_in = (const struct sockaddr_in *)addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
    int port = ntohs(addr_in->sin_port);

    if (strcmp(ip_str, GATEWAY_IP) == 0 && port == GATEWAY_PORT) {
      // intercept if it is trying to connect to the gateway
      fprintf(stderr, "[Shim] Intercepting %s:%d -> Redirecting to %s:%d\n",
              ip_str, port, SIDECAR_IP, SIDECAR_PORT);
      struct sockaddr_in sidecar_addr;
      memset(&sidecar_addr, 0, sizeof(sidecar_addr));
      sidecar_addr.sin_family = AF_INET;
      sidecar_addr.sin_port = htons(SIDECAR_PORT);
      if (inet_pton(AF_INET, SIDECAR_IP, &sidecar_addr.sin_addr) <= 0) {
        fprintf(stderr, "[Shim] Error: Failed to convert Sidecar IP\n");
        return -1;
      }
      return real_connect(sockfd, (struct sockaddr *)&sidecar_addr,
                          sizeof(sidecar_addr));
    }
  }
  return real_connect(sockfd, addr, addrlen);
}
