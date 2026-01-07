#include <boost/algorithm/string/join.hpp>
#include <string>
#include <unordered_map>
#include <vector>

#include "gateway_client.h"
#include "lib/httplib.h"
#include "watchdog.h"

namespace {
bool enable_interception = false;

std::unordered_map<int, std::vector<int>> GenerateFollowers(int count) {
  std::unordered_map<int, std::vector<int>> db;
  db.reserve(count);

  for (int i = 0; i < count; ++i) {
    std::vector<int> users;
    for (int j = 0; j < i; j++) { users.push_back(j); }
    db[i] = users;
  }
  return db;
}

std::unordered_map<int, std::vector<int>> followers_db = GenerateFollowers(100);

void GetFollowersHandler(const httplib::Request &req, httplib::Response &res) {
  try {
    int user_id = std::stoi(req.path_params.at("id"));
    const std::vector<int> &followers = followers_db.at(user_id);
    std::string req_path = "/user/";
    std::vector<std::string> names;
    for (const int &id : followers) {
      names.push_back(
          CallGateway(req_path + std::to_string(id), enable_interception));
    }
    res.set_content(boost::algorithm::join(names, ", "), "text/plain");
  } catch (...) {
    res.status = httplib::StatusCode::NotFound_404;
    res.set_content("User does exist", "text/plain");
  }
}
}  // namespace

int main(int argc, char *argv[]) {
  if (argc > 1 && std::strcmp(argv[1], "--int") == 0) {
    enable_interception = true;
  }
  WatchDog w("follower", "/followers/:id", GetFollowersHandler);
  w.Run();
  return 0;
}
