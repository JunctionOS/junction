// strace_maps.h - constant maps and sets for strace functionality

#pragma once

#include <map>
#include <set>
#include <string>

namespace junction {
namespace strace {

// Forward declarations for all const maps and sets
extern const std::map<int, std::string> protection_flags;
extern const std::map<int, std::string> mmap_flags;
extern const std::map<int, std::string> open_flags;
extern const std::map<int, std::string> madvise_hints;
extern const std::map<int, std::string> clone_flags;
extern const std::map<int, std::string> futex_flags;
extern const std::set<int> futex_ops_with_val2;
extern const std::set<int> futex_ops_with_timeout;
extern const std::map<int, std::string> ioctls;
extern const std::map<int, std::string> fcntls;
extern const std::map<int, std::string> statx_mask_flags;
extern const std::map<int, std::string> at_flags;
extern const std::map<int, std::string> poll_flags;
extern const std::map<int, std::string> prctl_ops;
extern const std::map<int, std::string> sock_domains;
extern const std::map<int, std::string> sock_types;
extern const std::map<int, std::string> msg_flags;
extern const std::map<int, std::string> epoll_ctl_ops;
extern const std::map<int, std::string> sigprocmask_how;
extern const std::map<int, std::string> wait_flags;
extern const std::map<int, std::string> sockopt_levels;
extern const std::map<int, std::string> sock_options;
extern const std::set<int> intlike_sockopts;
extern const std::map<int, std::string> ip_options;
extern const std::set<int> ip_int_options;

// Signal map array
extern const char *sigmap[];
constexpr size_t kNumSignals = 32;

}  // namespace strace
}  // namespace junction
