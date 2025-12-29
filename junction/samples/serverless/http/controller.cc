#include <iostream>

#include "lib/httplib.h"

constexpr int CONTROLLER_PORT = 8080;

namespace {

void GetUserHandler(const httplib::Request &req, httplib::Response &res) {
  // TODO: write request to socket and read back response
  res.set_content("Test", "text/plain");
}

bool InitServer() {
  httplib::Server svr;

  svr.Get("/user", GetUserHandler);

  std::cout << "[Controller] Listening on " << "0.0.0.0" << ":"
            << CONTROLLER_PORT << std::endl;

  return svr.listen("0.0.0.0", CONTROLLER_PORT);
}
}  // namespace

int main() {
  if (!InitServer()) {
    std::cerr << "[Controller] Failed to listen on port: " << CONTROLLER_PORT
              << std::endl;
    exit(1);
  }
  return 0;
}
