#include <boost/algorithm/string/join.hpp>
#include <string>
#include <unordered_map>
#include <vector>

#include "gateway_client.h"
#include "watchdog.h"

namespace {
std::unordered_map<int, std::vector<int>> followers_db = {
    {0, {1, 2}},     // Alice is followed by Bob and Carrol
    {1, {2}},        // Bob is followed by Carrol
    {2, {0, 3}},     // Carrol is followed by Alice and David
    {3, {0, 1, 2}},  // David is followed by Alice, Bob, and Carrol
};

std::string GetFollowersHandler(int user_id) {
  try {
    std::vector<int> followers = followers_db.at(user_id);
    std::string req = "GET /user/";
    std::vector<std::string> names;
    for (const int &id : followers) {
      names.push_back(CallGateway(req + std::to_string(id)));
    }
    return boost::algorithm::join(names, ", ");
  } catch (...) { return "User not found"; }
}

std::string FollowerLogic(const std::string &method, const std::string &path,
                          const std::string &body) {
  std::string res;
  if (method == "GET" && path.rfind("/followers/", 0) == 0) {
    try {
      int user_id = std::stoi(path.substr(11));
      res = GetFollowersHandler(user_id);
    } catch (...) { res = "Invalid user id"; }
  } else {
    res = "Invalid Request";
  }
  return res;
}
}  // namespace

int main() {
  WatchDog w("follower", FollowerLogic);
  w.Run();
  return 0;
}
