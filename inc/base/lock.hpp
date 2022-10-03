#pragma once

#include <memory>
#include <mutex>

namespace junction {

class Lock {
public:
  Lock() = default;

  void lock() { _std_mutex.lock(); }

  void unlock() { _std_mutex.unlock(); }

  /* no copying or moving*/
  Lock(const Lock&) = delete;
  Lock& operator=(const Lock&) = delete;
  Lock(Lock&&) = delete;
  Lock& operator=(const Lock&&) = delete;

private:
  std::mutex _std_mutex;
};

} // namespace junction