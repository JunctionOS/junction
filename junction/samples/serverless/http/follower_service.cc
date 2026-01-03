#include <boost/algorithm/string/join.hpp>
#include <string>
#include <unordered_map>
#include <vector>

#include "gateway_client.h"
#include "lib/httplib.h"
#include "watchdog.h"

namespace {
std::unordered_map<int, std::vector<int>> followers_db = {
    {0, {1, 2}},     // Alice is followed by Bob and Carrol
    {1, {2}},        // Bob is followed by Carrol
    {2, {0, 3}},     // Carrol is followed by Alice and David
    {3, {0, 1, 2}},  // David is followed by Alice, Bob, and Carrol
};

void GetFollowersHandler(const httplib::Request &req, httplib::Response &res) {
  try {
    int user_id = std::stoi(req.path_params.at("id"));
    const std::vector<int> &followers = followers_db.at(user_id);
    std::string req_path = "/user/";
    std::vector<std::string> names;
    for (const int &id : followers) {
      names.push_back(CallGateway(req_path + std::to_string(id)));
    }
    res.set_content(boost::algorithm::join(names, ", "), "text/plain");
  } catch (...) {
    res.status = httplib::StatusCode::NotFound_404;
    res.set_content("User does exist", "text/plain");
  }
}
}  // namespace

int main() {
  WatchDog w("follower", "/followers/:id", GetFollowersHandler);
  w.Run();
  return 0;
}
