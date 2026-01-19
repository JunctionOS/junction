#include <iostream>

#include "lib/httplib.h"

namespace {

constexpr int PROXY_PORT = 9000;
const std::string USER_SOCK = "/tmp/serverless/user.sock";

void ProxyHandler(const httplib::Request &req, httplib::Response &res) {
  if (req.method != "GET" || req.path.find("/user/") == std::string::npos) {
    res.status = httplib::StatusCode::MethodNotAllowed_405;
    res.set_content("Method not allowed", "text/plain");
    return;
  }
  httplib::Client cli(USER_SOCK);
  cli.set_address_family(AF_UNIX);
  auto func_res = cli.Get(req.path, req.headers);
  if (func_res) {
    res.status = func_res->status;
    res.body = func_res->body;
    for (const auto &header : func_res->headers) {
      if (header.first != "content-length" &&
          header.first != "transfer-encoding") {
        res.set_header(header.first, header.second);
      }
    }
  } else {
    res.status = httplib::StatusCode::BadGateway_502;
    res.set_content("Bad Gateway: Function Unreachable", "text/plain");
  }
}
}  // namespace

int main() {
  httplib::Server svr;
  svr.Get(".*", ProxyHandler);
  svr.Post(".*", ProxyHandler);
  svr.Put(".*", ProxyHandler);
  svr.Delete(".*", ProxyHandler);

  std::cout << "[Proxy Service] Listening on 0.0.0.0:" << PROXY_PORT
            << std::endl;
  if (!svr.listen("0.0.0.0", PROXY_PORT)) {
    std::cerr << "[Proxy Service] Server failed to listen" << std::endl;
    exit(1);
  }
  return 0;
}
