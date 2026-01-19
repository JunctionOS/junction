#include "watchdog.h"

#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "lib/httplib.h"

constexpr const char *SOCK_DIR = "/tmp/serverless/";
constexpr const char *SOCK_EXT = ".sock";

WatchDog::WatchDog(const std::string &name, const std::string &req_path,
                   httplib::Server::Handler h)
    : handler_(std::move(h)) {
  sock_path_ = SOCK_DIR + name + SOCK_EXT;
  req_path_ = req_path;
}

bool WatchDog::InitServer() {
  struct stat st = {0};
  if (stat(SOCK_DIR, &st) == -1) {
    if (mkdir(SOCK_DIR, 0777) != 0 && errno != EEXIST) {
      std::cerr << "[Watchdog] Failed to create directory: " << SOCK_DIR
                << std::endl;
      return false;
    }
  }
  unlink(sock_path_.c_str());

  httplib::Server svr;
  svr.Get(req_path_, handler_);

  if (!svr.set_address_family(AF_UNIX).listen(sock_path_, 80)) {
    std::cerr << "[Watchdog] Failed to listen on " << sock_path_ << std::endl;
    return false;
  }

  return true;
}

void WatchDog::Run() {
  if (!InitServer()) { exit(1); }
}
