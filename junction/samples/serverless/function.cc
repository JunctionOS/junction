#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

constexpr const char *CHANNEL_PATH = "/serverless/chan0";
constexpr const char *SNAPSHOT_REQ = "SNAPSHOT_PREPARE";
constexpr const char *OK = "OK";

namespace {

std::fstream channel;

bool OpenChannel() {
  channel.open(CHANNEL_PATH);

  if (!channel.is_open()) {
    std::cerr << "Failed to open serverless channel" << std::endl;
    return false;
  }
  std::cout << "Function process started. Waiting for requests on "
            << CHANNEL_PATH << std::endl;
  return true;
}

bool Warmup() {
  std::cout << "Handling warmup process" << std::endl;
  std::string req_line;
  while (true) {
    if (!std::getline(channel, req_line)) {
      std::cerr << "Failed to read warmup request" << std::endl;
      return false;
    }

    std::cout << "Recieved request: " << req_line << std::endl;
    if (req_line == SNAPSHOT_REQ) {
      channel << OK;
      std::cout << "Sent snapshot OK response." << std::endl;
      break;
    }
    channel << "Processed: " << req_line;
  }
  std::cout << "Completed warmup process" << std::endl;
  return true;
}

std::unordered_map<int, std::string> users = {
    {0, "Alice"}, {1, "Bob"}, {2, "Carrol"}, {3, "David"}};
int count = 4;

void GetUserHandler(int user_id) {
  try {
    std::string_view user = users.at(user_id);
    channel << user;
  } catch (...) { channel << "User not found"; }
}

void AddUserHandler(const std::string &name) {
  users.insert({count, name});
  channel << "Added {" << count << ": " << name << "}";
  count++;
}

bool Router() {
  std::string req_line;
  if (!std::getline(channel, req_line)) {
    std::cerr << "Failed to read request" << std::endl;
    return false;
  }

  std::string res;
  std::stringstream ss(req_line);
  std::string method;
  std::string path;
  std::string name;
  ss >> method;
  ss >> path;
  if (method == "GET" && path.rfind("/user/", 0) == 0) {
    int user_id = std::stoi(path.substr(6));
    GetUserHandler(user_id);
  } else if (method == "POST" && path == "/user") {
    ss >> name;
    AddUserHandler(name);
  } else {
    res = "Invalid Request: " + req_line;
    channel << res;
  }
  return true;
}

void CloseChannel() { channel.close(); }

}  // namespace

int main() {
  if (!OpenChannel()) { return 1; }

  if (!Warmup()) {
    CloseChannel();
    return 1;
  }

  while (Router()) {}

  CloseChannel();

  return 0;
}
