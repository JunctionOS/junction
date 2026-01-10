#include <spawn.h>

#include <iostream>

#include "lib/httplib.h"

extern char **environ;

const std::string CURR_DIR = "./samples/serverless/http/";
const std::string USER_BIN = "user_service";
const std::string FOLLOWER_BIN = "follower_service";
const std::string PROXY_BIN = "proxy_service";

constexpr int CONTROLLER_PORT = 8080;

const std::string SOCK_PATH = "/tmp/serverless/";
const std::string USER_SOCK = "user.sock";
const std::string FOLLOWER_SOCK = "follower.sock";

const std::string SHIM_SO = "libshim.so";

namespace {

bool SpawnService(const std::string &bin, bool enable_interception) {
  // create args
  std::vector<char *> args;
  args.push_back(const_cast<char *>(bin.c_str()));
  args.push_back(nullptr);

  // create envs
  std::vector<char *> envs;
  for (char **env = environ; *env != nullptr; env++) { envs.push_back(*env); }
  std::string preload_str;
  if (enable_interception) {
    preload_str = "LD_PRELOAD=" + CURR_DIR + SHIM_SO;
    envs.push_back(const_cast<char *>(preload_str.c_str()));
  }
  envs.push_back(nullptr);

  // log command
  std::stringstream log_ss;
  log_ss << "[Controller] Spawning: ";
  if (enable_interception) { log_ss << preload_str << " "; }
  for (auto *arg : args) {
    if (arg != nullptr) { log_ss << arg << " "; }
  }
  std::cout << log_ss.str() << std::endl;

  // spawn
  pid_t pid;
  if (posix_spawn(&pid, bin.c_str(), nullptr, nullptr, args.data(),
                  envs.data()) == 0) {
    std::cout << "[Controller] Service spawned successfuly. PID: " << pid
              << std::endl;
    return true;
  }
  std::cerr << "[Controller] Failed to spawn service: " << bin << std::endl;
  return false;
}

httplib::Server::Handler SocketHandler(const std::string &sock_path) {
  return [sock_path](const httplib::Request &req, httplib::Response &res) {
    std::cout << "[Controller] Recieved request: " << req.path << std::endl;
    httplib::Client cli(sock_path);
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
  };
}

bool InitServer() {
  httplib::Server svr;

  svr.Get("/user/:id", SocketHandler(SOCK_PATH + USER_SOCK));
  svr.Get("/followers/:id", SocketHandler(SOCK_PATH + FOLLOWER_SOCK));

  std::cout << "[Controller] Listening on " << "0.0.0.0" << ":"
            << CONTROLLER_PORT << std::endl;

  return svr.listen("0.0.0.0", CONTROLLER_PORT);
}
}  // namespace

int main(int argc, char *argv[]) {
  bool enable_interception = false;
  if (argc > 1 && std::strcmp(argv[1], "--int") == 0) {
    enable_interception = true;
    std::cout << "[Controller] Interception enabled." << std::endl;
  }
  if (!SpawnService(CURR_DIR + USER_BIN, enable_interception)) { exit(1); }
  if (!SpawnService(CURR_DIR + FOLLOWER_BIN, enable_interception)) { exit(1); }
  if (!SpawnService(CURR_DIR + PROXY_BIN, false)) { exit(1); }

  if (!InitServer()) {
    std::cerr << "[Controller] Failed to listen on port: " << CONTROLLER_PORT
              << std::endl;
    exit(1);
  }
  return 0;
}
