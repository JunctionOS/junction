#include <string>
#include <unordered_map>

#include "watchdog.h"

namespace {
std::unordered_map<int, std::string> users_db = {
    {0, "Alice"}, {1, "Bob"}, {2, "Carrol"}, {3, "David"}};
int count = 4;

std::string GetUserHandler(int user_id) {
  try {
    std::string user = users_db.at(user_id);
    return user;
  } catch (...) { return "User not found"; }
}

std::string AddUserHandler(const std::string &name) {
  users_db.insert({count, name});
  std::string res = "Added {" + std::to_string(count) + ": " + name + "}";
  count++;
  return res;
}

std::string UserLogic(const std::string &method, const std::string &path,
                      const std::string &body) {
  std::string res;
  if (method == "GET" && path.rfind("/user/", 0) == 0) {
    try {
      int user_id = std::stoi(path.substr(6));
      res = GetUserHandler(user_id);
    } catch (...) { res = "Invalid user id"; }
  } else if (method == "POST" && path == "/user") {
    res = AddUserHandler(body);
  } else {
    res = "Invalid Request";
  }
  return res;
}
}  // namespace

int main() {
  WatchDog w("user", UserLogic);
  w.Run();
  return 0;
}
