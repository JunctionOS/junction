#pragma once

#include <string>

#include "lib/httplib.h"

class WatchDog {
 public:
  explicit WatchDog(const std::string &name, const std::string &req_path,
                    httplib::Server::Handler h);
  void Run();

 private:
  std::string sock_path_;
  std::string req_path_;
  httplib::Server::Handler handler_;

  bool InitServer();
};
