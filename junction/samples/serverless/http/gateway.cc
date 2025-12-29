#include <algorithm>
#include <iostream>
#include <vector>

#include "lib/httplib.h"

constexpr int GATEWAY_PORT = 8080;
constexpr const char *CONTROLLER_IP = "10.10.1.2";
constexpr int CONTROLLER_PORT = 8080;

constexpr int TIMEOUT_US = 300000;

struct RequestRoute {
  std::string method;
  std::string path_prefix;
};

const std::vector<RequestRoute> ALLOWED_ROUTES = {
    {"GET", "/user"}, {"POST", "/user"}, {"GET", "/followers"}};

namespace {

bool IsValidRequestRoute(std::string_view method, std::string_view path) {
  return std::any_of(ALLOWED_ROUTES.begin(), ALLOWED_ROUTES.end(),
                     [method, path](const RequestRoute &r) {
                       return r.method == method &&
                              path.find(r.path_prefix) == 0;
                     });
}

void ProxyHandler(const httplib::Request &req, httplib::Response &res) {
  if (!IsValidRequestRoute(req.method, req.path)) {
    std::cout << "[Gateway] BLOCKED: " << req.method << " " << req.path
              << std::endl;
    res.status = httplib::StatusCode::NotFound_404;
    res.set_content("Route not found or method not allowed", "text/plain");
    return;
  }

  std::cout << std::unitbuf << "[Gateway] Forwarding " << req.method << " "
            << req.path << std::endl;

  httplib::Client cli(CONTROLLER_IP, CONTROLLER_PORT);
  // cli.set_connection_timeout(0, TIMEOUT_US);

  httplib::Result ctrl_res;
  if (req.method == "GET") {
    ctrl_res = cli.Get(req.path, req.headers);
  } else if (req.method == "POST") {
    ctrl_res = cli.Post(req.path, req.headers, req.body,
                        req.get_header_value("Content-Type"));
  } else if (req.method == "PUT") {
    ctrl_res = cli.Put(req.path, req.headers, req.body,
                       req.get_header_value("Content-Type"));
  } else if (req.method == "DELETE") {
    ctrl_res = cli.Delete(req.path, req.headers);
  }

  if (ctrl_res) {
    res.status = ctrl_res->status;
    res.body = ctrl_res->body;
    for (const auto &header : ctrl_res->headers) {
      if (header.first != "Content-Length" &&
          header.first != "Transfer-Encoding") {
        res.set_header(header.first, header.second);
      }
    }
  } else {
    res.status = httplib::StatusCode::BadGateway_502;
    res.set_content("Bad Gateway: Controller Unreachable", "text/plain");
  }
}

}  // namespace

int main() {
  httplib::Server svr;

  svr.Get(".*", ProxyHandler);
  svr.Post(".*", ProxyHandler);
  svr.Put(".*", ProxyHandler);
  svr.Delete(".*", ProxyHandler);

  std::cout << "[Gateway] Listening on " << "0.0.0.0" << ":" << GATEWAY_PORT
            << std::endl;
  if (!svr.listen("0.0.0.0", GATEWAY_PORT)) {
    std::cerr << "[Gateway] Server failed to listen" << std::endl;
    exit(1);
  }

  return 0;
}
