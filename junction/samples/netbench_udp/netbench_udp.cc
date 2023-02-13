// Source:
// https://github.com/shenango/caladan/blob/main/apps/bench/netbench_udp.cc
// Note: With some modifications to run with the Linux socket APIs.

extern "C" {
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "stdio.h"
}
#undef min
#undef max

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <thread>
#include <utility>
#include <vector>

#include "fake_worker.h"
#include "proto.h"
#include "timing.h"

#define barrier() asm volatile("" ::: "memory")

#define panic(fmt, ...)                  \
  do {                                   \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    exit(1);                             \
  } while (0)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

namespace {

using sec = std::chrono::duration<double, std::micro>;

// Active threads.
std::atomic<bool> all_started;
std::atomic<unsigned> remaining;

// UDP payload size.
static constexpr size_t kMaxPayloadSize = 2048;
// The number of samples to discard from the start and end.
constexpr uint64_t kDiscardSamples = 10;  // TODO(girfan): 1000?
// The maximum lateness to tolerate before dropping egress samples.
constexpr uint64_t kMaxCatchUpUS = 50000;  // TODO(girfan): Should be 5?

// the number of worker threads to spawn.
int threads;
// the remote UDP address of the server.
sockaddr_in raddr;
// the length of the remote UDP address of the server.
const socklen_t raddrlen = sizeof(sockaddr_in);
// the number of samples to gather.
uint64_t n;
// the mean service time in us.
double st;

void ServerWorker(int c) {
  union {
    unsigned char buf[kMaxPayloadSize];
    payload p;
  };
  std::unique_ptr<FakeWorker> w(FakeWorkerFactory("stridedmem:3200:64"));
  if (unlikely(w == nullptr)) panic("couldn't create worker\n");

  while (true) {
    // Receive a network response.
    struct sockaddr_in sender;
    socklen_t slen = sizeof(sender);
    ssize_t ret = recvfrom(c, &buf, sizeof(buf), 0,
                           reinterpret_cast<sockaddr*>(&sender), &slen);
    if (ret <= 0 || ret > static_cast<ssize_t>(sizeof(buf))) {
      if (ret == 0) break;
      perror("recvfrom");
      panic("udp read failed, ret = %ld errno %d\n", ret, errno);
    }

    // Determine if the connection is being killed.
    if (unlikely(p.tag == kKill)) {
      shutdown(c, SHUT_RDWR);
      break;
    }

    // Perform fake work if requested.
    if (p.workn != 0) w->Work(p.workn * 82.0);

    // Send a network request.
    ssize_t sret = sendto(c, &buf, ret, 0, reinterpret_cast<sockaddr*>(&sender),
                          sizeof(sender));
    if (sret != ret) {
      if (sret == -EPIPE) break;
      perror("sendto");
      panic("[ServerWorker] udp write failed, ret = %ld\n", sret);
    }
  }
}

void ServerHandler() {
  int c;
  sockaddr_in in;

  c = socket(AF_INET, SOCK_DGRAM, 0);
  if (c == -1) {
    perror("socket");
    return;
  }

  in.sin_family = AF_INET;
  in.sin_port = htons(kNetbenchPort);
  in.sin_addr.s_addr = 0;

  char str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(in.sin_addr), str, INET_ADDRSTRLEN) == NULL)
    panic("cannot inet_ntop\n");

  printf("Waiting on IP: %s\n", str);

  if (bind(c, reinterpret_cast<sockaddr*>(&in), sizeof(in)) == -1)
    panic("cannot bind\n");

  while (true) {
    nbench_req req;
    sockaddr_in raddr;
    socklen_t addrlen = sizeof(raddr);
    ssize_t ret = recvfrom(c, &req, sizeof(req), 0 /* flags */,
                           reinterpret_cast<sockaddr*>(&raddr), &addrlen);
    if (ret != sizeof(req) || req.magic != kMagic) continue;

    char str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(raddr.sin_addr), str, INET_ADDRSTRLEN) == NULL) {
      panic("inet_ntop failed\n");
    }

    printf("Received from IP: %s\n", str);

    std::thread([=, &c]() {
      printf("Got connection %x:%d, %d ports\n", raddr.sin_addr.s_addr,
             raddr.sin_port, req.nports);

      union {
        nbench_resp resp;
        char buf[kMaxPayloadSize];
      };
      resp.magic = kMagic;
      resp.nports = req.nports;

      std::vector<std::thread> threads;

      // Create the worker threads.
      std::vector<int> conns;
      for (int i = 0; i < req.nports; ++i) {
        int cin = socket(AF_INET, SOCK_DGRAM, 0);
        if (cin < 0) panic("couldn't create socket\n");

        struct sockaddr_in ephem = {0};
        ephem.sin_family = AF_INET;
        int ret =
            bind(cin, reinterpret_cast<const sockaddr*>(&ephem), sizeof(ephem));
        if (ret) panic("couldn't connect socket\n");

        sockaddr_in laddr;
        socklen_t laddrlen = sizeof(laddr);
        ret = getsockname(cin, reinterpret_cast<sockaddr*>(&laddr), &laddrlen);
        if (ret) panic("couldn't getsockname\n");

        resp.ports[i] = laddr.sin_port;
        threads.emplace_back(std::thread(std::bind(ServerWorker, cin)));
        conns.emplace_back(cin);
      }

      // Send the port numbers to the client.
      ssize_t len = sizeof(nbench_resp) + sizeof(uint16_t) * req.nports;
      if (len > static_cast<ssize_t>(kMaxPayloadSize)) panic("too big\n");

      char str[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &(raddr.sin_addr), str, INET_ADDRSTRLEN) == NULL) {
        panic("inet_ntop failed\n");
      }

      printf("Sending to IP: %s\n", str);

      ssize_t ret = sendto(c, &resp, len, 0 /* flags */,
                           reinterpret_cast<const sockaddr*>(&raddr), addrlen);
      if (ret != len) {
        perror("sendto");
        fprintf(stderr, "[ServerHandler] udp write failed, ret = %ld\n", ret);
      }

      for (auto& t : threads) t.join();

      printf("done\n");
    }).detach();
  }
}

void KillConn(int c) {
  constexpr int kKillRetries = 10;
  union {
    unsigned char buf[32];
    payload p;
  };
  p.tag = kKill;
  for (int i = 0; i < kKillRetries; ++i) {
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int ret = getpeername(c, reinterpret_cast<sockaddr*>(&addr), &addrlen);
    if (ret) panic("getpeername failed, ret = %d\n", ret);
    ret = sendto(c, buf, sizeof(buf), 0 /* flags */,
                 reinterpret_cast<sockaddr*>(&addr), addrlen);
    if (!ret) panic("sendto failed, ret = %d\n", ret);
  }
}

std::vector<double> PoissonWorker(int c, double req_rate, double service_time) {
  // Seed the random generator with the local port number.
  sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  int ret = getpeername(c, reinterpret_cast<sockaddr*>(&addr), &addrlen);
  if (ret) panic("getpeername failed, ret = %d\n", ret);
  std::mt19937 g(addr.sin_port);

  // Create a packet transmit schedule.
  std::vector<double> sched;
  std::exponential_distribution<double> rd(1.0 / (1000000.0 / req_rate));
  std::vector<double> tmp(n);
  std::generate(tmp.begin(), tmp.end(), std::bind(rd, g));
  sched.push_back(tmp[0]);
  for (std::vector<double>::size_type j = 1; j < tmp.size(); ++j) {
    tmp[j] += tmp[j - 1];
    sched.push_back(static_cast<uint64_t>(tmp[j]));
  }

  // Create a fake work schedule.
  std::vector<double> work(n);
  std::exponential_distribution<double> wd(1.0 / service_time);
  std::generate(work.begin(), work.end(), std::bind(wd, g));

  // Reserve space to record results.
  auto n = sched.size();
  std::vector<double> timings;
  timings.reserve(n);
  std::vector<uint64_t> start_us(n);

  // Start the receiver thread.
  auto th = std::thread([&] {
    union {
      unsigned char rbuf[32] = {};
      payload rp;
    };

    while (true) {
      ssize_t ret = read(c, rbuf, sizeof(rbuf));
      if (ret != static_cast<ssize_t>(sizeof(rbuf))) {
        if (ret == 0) break;
        perror("read");
        panic("udp read failed, ret = %ld\n", ret);
      }

      barrier();
      uint64_t ts = microtime();
      barrier();
      timings.push_back(ts - start_us[rp.idx]);
    }
  });

  // Initialize timing measurement data structures.
  union {
    unsigned char buf[32] = {};
    payload p;
  };

  // Synchronized start of load generation.
  remaining--;
  if (remaining.load() == 0) {
    all_started = true;
    all_started.notify_all();
  }
  all_started.wait(false);

  barrier();
  uint64_t expstart = microtime();
  barrier();

  for (unsigned int i = 0; i < n; ++i) {
    barrier();
    uint64_t now = microtime();
    barrier();
    if (now - expstart < sched[i]) {
      uint64_t sleep_dur = sched[i] - (now - expstart);
      std::this_thread::sleep_for(std::chrono::microseconds(sleep_dur));
      now = microtime();
    }
    double diff = now - expstart - sched[i];
    if (diff > kMaxCatchUpUS) {
      continue;
    }

    barrier();
    start_us[i] = microtime();
    barrier();

    // Send a network request.
    p.idx = i;
    p.workn = work[i];
    p.tag = 0;

    ssize_t ret = send(c, buf, sizeof(buf), 0 /* flags */);
    if (ret != static_cast<ssize_t>(sizeof(buf)))
      panic("[PoissonWorker] udp write failed, ret = %ld\n", ret);
  }

  shutdown(c, SHUT_RDWR);
  th.join();

  return timings;
}

std::vector<double> RunExperiment(double req_rate, double* reqs_per_sec) {
  int c = socket(AF_INET, SOCK_DGRAM, 0);
  if (c < 0) panic("couldn't create socket\n");

  int err = connect(c, reinterpret_cast<sockaddr*>(&raddr), raddrlen);
  if (err) panic("couldn't connect socket, ret = %d\n", err);

  // Send the control message.
  nbench_req req = {kMagic, threads};
  ssize_t ret = write(c, &req, sizeof(req));
  if (ret != sizeof(req)) panic("couldn't send control message\n");

  // Receive the control response.
  union {
    nbench_resp resp;
    char buf[kMaxPayloadSize];
  };
  ret = read(c, &resp, kMaxPayloadSize);
  if (ret < static_cast<ssize_t>(sizeof(nbench_resp)))
    panic("failed to receive control response, ret = %ld\n", ret);
  if (resp.magic != kMagic || resp.nports != threads)
    panic("got back invalid control response\n");

  // Create one UDP connection per thread.
  std::vector<int> conns;
  for (int i = 0; i < threads; ++i) {
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = resp.ports[i];
    addr.sin_addr.s_addr = raddr.sin_addr.s_addr;

    int outc = socket(AF_INET, SOCK_DGRAM, 0);
    if (outc < 0) panic("couldn't create socket\n");

    int ret = connect(outc, reinterpret_cast<sockaddr*>(&addr), addrlen);
    if (ret) panic("couldn't connect socket\n");

    conns.emplace_back(std::move(outc));
  }

  // Launch a worker thread for each connection.
  remaining.store(threads + 1);
  std::vector<std::thread> th;
  std::unique_ptr<std::vector<double>> samples[threads];
  for (int i = 0; i < threads; ++i) {
    th.emplace_back(std::thread([&, i] {
      auto v = PoissonWorker(conns[i], req_rate / threads, st);
      samples[i].reset(new std::vector<double>(std::move(v)));
    }));
  }

  // Give the workers time to initialize, then start recording.
  remaining--;
  if (remaining.load() == 0) {
    all_started = true;
    all_started.notify_all();
  }
  all_started.wait(false);

  // |--- start experiment duration timing ---|
  barrier();
  auto start = microtime();
  barrier();

  // Wait for the workers to finish.
  for (auto& t : th) t.join();

  // |--- end experiment duration timing ---|
  barrier();
  auto finish = microtime();
  barrier();

  // Close the connections.
  for (auto& c : conns) KillConn(c);

  // Aggregate all the latency timings together.
  uint64_t total = 0;
  std::vector<double> timings;
  for (int i = 0; i < threads; ++i) {
    auto& v = *samples[i];
    total += v.size();
    if (v.size() <= kDiscardSamples * 2)
      panic("not enough samples (%ld <= %ld)\n", v.size(), kDiscardSamples * 2);
    v.erase(v.begin(), v.begin() + kDiscardSamples);
    v.erase(v.end() - kDiscardSamples, v.end());
    timings.insert(timings.end(), v.begin(), v.end());
  }

  // Report results.
  auto elapsed = finish - start;
  *reqs_per_sec = static_cast<double>(total) / elapsed * 1000000;
  return timings;
}

void DoExperiment(double req_rate) {
  constexpr int kRounds = 1;
  std::vector<double> timings;
  double reqs_per_sec = 0;
  for (int i = 0; i < kRounds; i++) {
    double tmp;
    auto t = RunExperiment(req_rate, &tmp);
    timings.insert(timings.end(), t.begin(), t.end());
    reqs_per_sec += tmp;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  reqs_per_sec /= kRounds;

  std::sort(timings.begin(), timings.end());
  double sum = std::accumulate(timings.begin(), timings.end(), 0.0);
  double mean = sum / timings.size();
  double count = static_cast<double>(timings.size());
  double p9 = timings[count * 0.9];
  double p99 = timings[count * 0.99];
  double p999 = timings[count * 0.999];
  double p9999 = timings[count * 0.9999];
  double min = timings[0];
  double max = timings[timings.size() - 1];
  std::cout << std::setprecision(2) << std::fixed << "t: " << threads
            << " rps: " << reqs_per_sec << " n: " << timings.size()
            << " min: " << min << " mean: " << mean << " 90%: " << p9
            << " 99%: " << p99 << " 99.9%: " << p999 << " 99.99%: " << p9999
            << " max: " << max << std::endl;
}

void ClientHandler() {
  for (double i = 500000; i <= 5000000; i += 500000) DoExperiment(i);
}

}  // anonymous namespace

int main(int argc, char* argv[]) {
  int err = time_init();
  if (err) {
    return err;
  }

  if (argc < 2) {
    std::cerr << "usage: <server|client> ..." << std::endl;
    return -EINVAL;
  }

  std::string cmd = argv[1];
  if (cmd.compare("server") == 0) {
    ServerHandler();
  } else if (cmd.compare("client") != 0) {
    std::cerr << "invalid command: " << cmd << std::endl;
    return -EINVAL;
  }

  if (argc != 6) {
    std::cerr << "usage: client [#threads] [remote_ip] [n] [service_us]"
              << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[2], nullptr, 0);

  raddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, argv[3], &raddr.sin_addr) != 1) {
    return -EINVAL;
  }
  raddr.sin_port = htons(kNetbenchPort);

  n = std::stoll(argv[4], nullptr, 0);
  st = std::stod(argv[5], nullptr);

  ClientHandler();

  return 0;
}
