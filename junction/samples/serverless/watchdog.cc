#include "watchdog.h"

#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

constexpr const char *CHANNEL_PATH_BASE = "/serverless/";
constexpr const char *SNAPSHOT_REQ = "SNAPSHOT_PREPARE";
constexpr const char *OK = "OK";

WatchDog::WatchDog(const std::string &name, RequestHandler h)
    : handler_(std::move(h)) {
  chan_path_ = CHANNEL_PATH_BASE + name;
}

bool WatchDog::OpenChannel() {
  channel_.open(chan_path_);

  if (!channel_.is_open()) {
    std::cerr << "[Watchdog] Failed to open serverless channel\n";
    return false;
  }

  // avoid buffering
  channel_ << std::unitbuf;

  std::cout << std::unitbuf
            << "[Watchdog] Function process started. Waiting for requests on "
            << chan_path_ << "\n";
  return true;
}

bool WatchDog::Warmup() {
  std::cout << std::unitbuf << "[Watchdog] Handling warmup process\n";
  std::string req_line;
  while (true) {
    if (!std::getline(channel_, req_line)) {
      std::cerr << "[Watchdog] Failed to read warmup request\n";
      return false;
    }

    std::cout << std::unitbuf << "[Watchdog] Recieved request: " << req_line
              << "\n";
    if (req_line == SNAPSHOT_REQ) {
      channel_ << OK;
      std::cout << std::unitbuf << "[Watchdog] Sent snapshot OK response.\n";
      break;
    }
    channel_ << "Processed: " << req_line;
  }
  std::cout << std::unitbuf << "[Watchdog] Completed warmup process\n";
  return true;
}

void WatchDog::Respond(const std::string &res) {
  std::cout << std::unitbuf
            << "[Wathdog] Forwarding response to function server...\n";
  std::lock_guard<std::mutex> lock(chan_mutex_);
  channel_ << res;
  std::cout << std::unitbuf
            << "[Wathdog] Forwarded response to function server\n";
}

void WatchDog::Worker(const std::string &req) {
  std::string res;
  std::stringstream ss(req);
  std::string method;
  std::string path;
  std::string body;
  if (!(ss >> method >> path)) {
    std::cerr << "[Watchdog] Invalid request: " << req << "\n";
    res = "Invalid request: " + req;
  } else {
    ss >> body;
    std::cout << std::unitbuf << "[Wathdog] Calling handler...\n";
    res = handler_(method, path, body);
    std::cout << std::unitbuf
              << "[Wathdog] Received response from handler: " << res << "\n";
  }
  Respond(res);
}

void WatchDog::ProcessRequest() {
  while (true) {
    std::cout << "[Watchdog] Waiting for request...\n";
    std::string req;
    if (!std::getline(channel_, req)) {
      std::cerr << "[Watchdog] Failed to read request\n";
      continue;
    }
    if (req == "restore") {
      std::cout
          << "[Watchdog] Resumed from snapshot. Ignoring restore signal.\n";
      Respond(OK);
      continue;
    }
    std::cout << "[Watchdog] Spawning a worker for request: " << req << "\n";
    std::thread(&WatchDog::Worker, this, req).detach();
  }
}

void WatchDog::Run() {
  if (!OpenChannel()) { exit(1); }

  if (!Warmup()) { exit(1); }

  ProcessRequest();
}
