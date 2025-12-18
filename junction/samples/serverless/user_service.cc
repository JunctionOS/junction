#include <fmt/core.h>

#include <string>
#include <unordered_map>

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
  count++;
  return fmt::format("Added {{{}: {}}}", count, name);
}

std::string UserLogic(const std::string &method, const std::string &path,
                      const std::string &body) {
  std::string res;
  if (method == "GET" && path.rfind("/user/", 0) == 0) {
    int user_id = std::stoi(path.substr(6));
    res = GetUserHandler(user_id);
  } else if (method == "POST" && path == "/user") {
    res = AddUserHandler(body);
  } else {
    res = "Invalid Request";
  }
  return res;
}
}  // namespace

int main() {
  // TODO: call watchdog with user logic
  return 0;
}
