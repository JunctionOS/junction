#include <string>
#include <unordered_map>

#include "watchdog.h"

namespace {

std::unordered_map<int, std::string> GenerateUsers(int count) {
  std::unordered_map<int, std::string> db;
  db.reserve(count);

  for (int i = 0; i < count; ++i) {
    std::string name = "user_" + std::to_string(i);
    db[i] = name;
  }
  return db;
}

std::unordered_map<int, std::string> users_db = GenerateUsers(100);

void GetUserHandler(const httplib::Request &req, httplib::Response &res) {
  std::cout << "[User] Received request: " << req.path << std::endl;
  try {
    int user_id = std::stoi(req.path_params.at("id"));
    std::string_view user = users_db.at(user_id);
    res.set_content(user.data(), "text/plain");
    std::cout << "[User] Responding with: " << user.data() << std::endl;
  } catch (...) {
    res.status = httplib::StatusCode::NotFound_404;
    res.set_content("User does exist", "text/plain");
  }
}

}  // namespace

int main() {
  WatchDog w("user", "/user/:id", GetUserHandler);
  w.Run();
  return 0;
}
