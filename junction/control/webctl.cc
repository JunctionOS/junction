#include <charconv>

#include "junction/base/string.h"
#include "junction/bindings/log.h"
#include "junction/bindings/net.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/proc.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

constexpr uint64_t kControlPort = 42;
constexpr size_t kBufSize = 1024;

const std::map<std::string, int, std::less<void>> SigNames = {
    {"SIGHUP", 1},     {"SIGINT", 2},   {"SIGQUIT", 3},    {"SIGILL", 4},
    {"SIGTRAP", 5},    {"SIGABRT", 6},  {"SIGIOT", 6},     {"SIGBUS", 7},
    {"SIGFPE", 8},     {"SIGKILL", 9},  {"SIGUSR1", 10},   {"SIGSEGV", 11},
    {"SIGUSR2", 12},   {"SIGPIPE", 13}, {"SIGALRM", 14},   {"SIGTERM", 15},
    {"SIGSTKFLT", 16}, {"SIGCHLD", 17}, {"SIGCONT", 18},   {"SIGSTOP", 19},
    {"SIGTSTP", 20},   {"SIGTTIN", 21}, {"SIGTTOU", 22},   {"SIGURG", 23},
    {"SIGXCPU", 24},   {"SIGXFSZ", 25}, {"SIGVTALRM", 26}, {"SIGPROF", 27},
    {"SIGWINCH", 28},  {"SIGIO", 29},
};

template <class T>
std::optional<T> StringToNum(const std::string_view &s) {
  const char *last = s.data() + s.length();
  T value;
  std::from_chars_result res = std::from_chars(s.data(), last, value);
  if (res.ec == std::errc() && res.ptr == last) return value;
  LOG(WARN) << "parse error";
  return std::nullopt;
}

std::shared_ptr<Process> ProcFromToken(const std::string_view &t) {
  std::optional<pid_t> p = StringToNum<pid_t>(t);
  if (!p) return {};

  std::shared_ptr<Process> proc = Process::Find(*p);
  if (!proc) LOG(WARN) << "ctl: failed to find proc with pid " << *p;
  return proc;
}

// Read one byte at a time from @c into @buf until a newline is encountered.
Status<void> ReadLine(rt::TCPConn &c, std::span<std::byte> buf) {
  while (buf.size()) {
    Status<size_t> ret = c.Read(buf.subspan(0, 1));
    if (!ret || *ret != 1) return MakeError(EPIPE);
    if (buf.front() == std::byte('\n')) {
      buf.front() = std::byte(0);
      return {};
    }
    buf = buf.subspan(1);
  }
  return MakeError(ENOSPC);
}

void SnapshotCmd(std::vector<std::string_view> &tokens) {
  if (tokens.size() != 4) {
    LOG(WARN) << "usage: snapshot <pid> <metadata file> <elf file>";
    return;
  }

  std::optional<pid_t> p = StringToNum<pid_t>(tokens[1]);
  if (!p) return;
  SnapshotPid(*p, tokens[2], tokens[3]);
}

void SignalCmd(std::vector<std::string_view> &tokens) {
  if (tokens.size() != 3) {
    LOG(WARN) << "usage: signal <pid> <signum>";
    return;
  }

  std::shared_ptr<Process> proc = ProcFromToken(tokens[1]);
  if (!proc) return;

  int signal;

  auto it = SigNames.find(tokens[2]);
  if (it != SigNames.end()) {
    signal = it->second;
  } else {
    std::optional<int> sig = StringToNum<int>(tokens[2]);
    if (!sig) return;
    signal = *sig;
  }

  proc->Signal(signal);
}

void TraceCmd(std::vector<std::string_view> &tokens) {
  auto usage = [] { LOG(WARN) << "usage: trace <pid> <true | false>"; };

  if (tokens.size() != 3) {
    usage();
    return;
  }

  bool do_trace = tokens[2] == "true";
  if (!do_trace && tokens[2] != "false") {
    usage();
    return;
  }

  std::shared_ptr<Process> proc = ProcFromToken(tokens[1]);
  if (!proc) return;

  if (do_trace)
    proc->get_mem_map().EnableTracing();
  else
    proc->get_mem_map().EndTracing();
}

void ControlWorker(rt::TCPConn &c) {
  char b[kBufSize];

  auto usage = [] { LOG(WARN) << "usage: <snapshot|signal|trace> ..."; };

  while (true) {
    Status<void> ret = ReadLine(c, readable_span(b, sizeof(b)));
    if (!ret) return;

    std::string cmd(b);
    LOG(INFO) << "Read cmd: " << cmd;

    std::vector<std::string_view> tokens = split(cmd, ' ');
    if (tokens[0] == "snapshot")
      SnapshotCmd(tokens);
    else if (tokens[0] == "signal")
      SignalCmd(tokens);
    else if (tokens[0] == "trace")
      TraceCmd(tokens);
    else
      usage();
  }
}

void ControlServer(rt::TCPQueue &q) {
  while (true) {
    Status<rt::TCPConn> c = q.Accept();
    if (!c) panic("couldn't accept a connection");
    rt::Spawn([c = std::move(*c)] mutable { ControlWorker(c); });
  }
}

Status<void> InitControlServer() {
  Status<rt::TCPQueue> q = rt::TCPQueue::Listen({0, kControlPort}, 4096);
  if (!q) return MakeError(q);

  rt::Spawn([q = std::move(*q)] mutable { ControlServer(q); });

  return {};
}

}  // namespace junction
