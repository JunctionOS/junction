#include "gateway_client.h"

#include <iostream>

#include "lib/httplib.h"

constexpr int GATEWAY_PORT = 8080;
constexpr const char *GATEWAY_IP = "10.10.1.1";
const std::string USER_SOCK = "/tmp/serverless/user.sock";

/**
 * @brief Call the gateway from a function when there is a function-to-function
 * invocation.
 *
 * @param req
 * @return response
 */
std::string CallGateway(std::string_view req, bool enable_interception) {
  if (enable_interception && req.find("/user/") != std::string::npos) {
    std::cout << "[CallGateway] Intercepted request: " << req << std::endl;
    httplib::Client sock_cli(USER_SOCK);
    sock_cli.set_address_family(AF_UNIX);
    auto sock_res = sock_cli.Get(std::string(req));
    return sock_res->body;
  }
  httplib::Client cli(GATEWAY_IP, GATEWAY_PORT);
  auto res = cli.Get(std::string(req));
  return res->body;
}
