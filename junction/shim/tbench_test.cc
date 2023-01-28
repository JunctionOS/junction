#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

extern "C" {
#include <fcntl.h>
#include <poll.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <unistd.h>
}

#include <gtest/gtest.h>

using us = std::chrono::duration<double, std::micro>;
constexpr int kMeasureRounds = 1000000;

int getMeasureRounds() {
  static int measure_rounds;

  if (measure_rounds) return measure_rounds;

  char *env = getenv("MEASURE_ROUNDS");
  if (!env)
    measure_rounds = kMeasureRounds;
  else
    measure_rounds = std::stoi(std::string(env));

  std::cout << "Measure rounds: " << measure_rounds << std::endl;

  return measure_rounds;
}

void BenchGetPid(int measure_rounds) {
  for (int i = 0; i < measure_rounds; ++i) {
    std::ignore = getpid();
  }
}

void BenchSpawnJoin(int measure_rounds) {
  for (int i = 0; i < measure_rounds; ++i) {
    auto th = std::thread([]() { ; });
    th.join();
  }
}

void BenchMMAP(int measure_rounds) {
  for (int i = 0; i < measure_rounds; ++i) {
    void *addr = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXPECT_FALSE(addr == MAP_FAILED);
    munmap(addr, 1 << 20);
  }
}

void BenchUncontendedMutex(int measure_rounds) {
  std::mutex m;
  volatile unsigned long foo = 0;

  for (int i = 0; i < measure_rounds; ++i) {
    std::unique_lock<std::mutex> l(m);
    foo++;
  }
}

void BenchYield(int measure_rounds) {
  auto th = std::thread([&]() {
    for (int i = 0; i < measure_rounds / 2; ++i) std::this_thread::yield();
  });

  for (int i = 0; i < measure_rounds / 2; ++i) std::this_thread::yield();

  th.join();
}

void BenchSemPingPong(int measure_rounds) {
  sem_t sem1, sem2;
  if (sem_init(&sem1, 0, 0)) assert(false);
  if (sem_init(&sem2, 0, 1)) assert(false);

  auto th = std::thread([&]() {
    for (int i = 0; i < measure_rounds / 2; ++i) {
      sem_wait(&sem1);
      sem_post(&sem2);
    }
  });

  for (int i = 0; i < measure_rounds / 2; ++i) {
    sem_wait(&sem2);
    sem_post(&sem1);
  }

  th.join();
  sem_destroy(&sem1);
  sem_destroy(&sem2);
}

void BenchCondvarPingPong(int measure_rounds) {
  std::mutex m;
  std::condition_variable cv;
  bool dir = false;  // shared and protected by @m.

  auto th = std::thread([&]() {
    std::unique_lock<std::mutex> l(m);
    for (int i = 0; i < measure_rounds / 2; ++i) {
      while (dir) cv.wait(l);
      dir = true;
      cv.notify_one();
    }
  });

  std::unique_lock<std::mutex> l(m);
  for (int i = 0; i < measure_rounds / 2; ++i) {
    while (!dir) cv.wait(l);
    dir = false;
    cv.notify_one();
  }

  th.join();
}

void BenchPipe(int measure_rounds) {
  static constexpr size_t kBufSize = 4096;
  int fds[2];
  int ret = pipe(fds);
  EXPECT_EQ(ret, 0);
  auto th = std::thread([out_fd = fds[1], measure_rounds]() {
    char buf[kBufSize];
    for (int i = 0; i < measure_rounds; i++) {
      ssize_t n = write(out_fd, buf, kBufSize);
      EXPECT_EQ(n, kBufSize);
    }
  });

  int in_fd = fds[0];
  char buf[kBufSize];
  for (int i = 0; i < measure_rounds; i++) {
    ssize_t n = read(in_fd, buf, kBufSize);
    EXPECT_EQ(n, kBufSize);
  }
  th.join();
  close(fds[0]);
  close(fds[1]);
}

void BenchPoll(int measure_rounds) {
  static constexpr size_t kBufSize = 64;
  static constexpr size_t kPollThreads = 100;
  size_t bytes_to_write = kBufSize * measure_rounds / kPollThreads;
  std::vector<pollfd> pfds(kPollThreads);

  for (size_t i = 0; i < kPollThreads; i++) {
    int pipefds[2];
    int ret = pipe2(pipefds, O_NONBLOCK);
    EXPECT_EQ(ret, 0);
    pfds[i].fd = pipefds[0];
    pfds[i].events = POLLIN;

    // Spawn a writer thread for this pipe.
    std::thread([out_fd = pipefds[1], bytes_to_write] {
      struct pollfd pfd;
      pfd.fd = out_fd;
      pfd.events = POLLOUT;
      char buf[kBufSize];
      size_t bytes_written = 0;
      while (bytes_written < bytes_to_write) {
        int ret = poll(&pfd, 1, -1);
        EXPECT_EQ(ret, 1);
        if ((pfd.revents & POLLOUT) == 0) continue;
        ssize_t n = write(out_fd, buf, kBufSize);
        EXPECT_GT(n, 0);
        bytes_written += n;
      }
      close(out_fd);
    }).detach();
  }

  // Now poll() and read() all the bytes written into the pipes.
  char buf[kBufSize];
  while (!pfds.empty()) {
    int ret = poll(pfds.data(), pfds.size(), -1);
    EXPECT_GT(ret, 0);
    for (auto it = pfds.begin(); it != pfds.end();) {
      const pollfd &pfd = *it;
      EXPECT_FALSE((pfd.revents & (POLLNVAL | POLLERR)) != 0);
      if (pfd.revents & POLLIN) {
        ssize_t n = read(pfd.fd, buf, kBufSize);
        EXPECT_GT(n, 0);
        ++it;
        continue;
      }
      if (pfd.revents & POLLHUP) {
        close(pfd.fd);
        it = pfds.erase(it);
        continue;
      }
      ++it;
    }
  }
}

void BenchSelect(int measure_rounds) {
  static constexpr size_t kBufSize = 64;
  static constexpr size_t kPollThreads = 100;
  size_t bytes_to_write = kBufSize * measure_rounds / kPollThreads;
  std::vector<int> fds(kPollThreads);

  for (size_t i = 0; i < kPollThreads; i++) {
    int pipefds[2];
    int ret = pipe2(pipefds, O_NONBLOCK);
    EXPECT_EQ(ret, 0);
    fds[i] = pipefds[0];

    // Spawn a writer thread for this pipe.
    std::thread([out_fd = pipefds[1], bytes_to_write] {
      char buf[kBufSize];
      size_t bytes_written = 0;
      fd_set rfds;
      FD_ZERO(&rfds);
      while (bytes_written < bytes_to_write) {
        FD_SET(out_fd, &rfds);
        int ret = select(out_fd + 1, nullptr, &rfds, nullptr, nullptr);
        EXPECT_EQ(ret, 1);
        EXPECT_TRUE(FD_ISSET(out_fd, &rfds));
        ssize_t n = write(out_fd, buf, kBufSize);
        EXPECT_GT(n, 0);
        bytes_written += n;
      }
      close(out_fd);
    }).detach();
  }

  // Now select() and read() all the bytes written into the pipes.
  char buf[kBufSize];
  fd_set rfds;
  FD_ZERO(&rfds);
  while (!fds.empty()) {
    for (int fd : fds) FD_SET(fd, &rfds);
    int ret = select(fds.back() + 1, &rfds, nullptr, nullptr, nullptr);
    EXPECT_GT(ret, 0);
    for (auto it = fds.begin(); it != fds.end();) {
      int fd = *it;
      if (!FD_ISSET(fd, &rfds)) {
        ++it;
        continue;
      }
      ssize_t n = read(fd, buf, kBufSize);
      EXPECT_GE(n, 0);
      if (n == 0) {
        close(fd);
        it = fds.erase(it);
        FD_CLR(fd, &rfds);
        continue;
      }
      ++it;
    }
  }
}

void PrintResult(std::string name, us time) {
  time /= getMeasureRounds();
  std::cout << "test '" << name << "' took " << time.count() << " us."
            << std::endl;
}

class ThreadingTest : public ::testing::Test {
 protected:
  // All tests add their timing measurements to this data structure.
  static std::vector<std::pair<const std::string, us>> results_;

  static void WaitForButtonPress() {
    // Check if the env variable is set to wait for button press before start
    // and stop. This is useful for tracing program execution (e.e., trace-cmd).
    static char *env = getenv("WAIT_START_STOP");
    if (!env) return;

    const std::string env_str(env);
    if (env_str.empty() || env_str == "0" || env_str == "false" ||
        env_str == "False")
      return;
    if (env_str != "1" || env_str != "true" || env_str != "True") return;

    std::cout << "ppid: " << getppid() << ", pid: " << getpid() << std::endl;
    std::cout << "Press ENTER to proceed..." << std::endl;
    getchar();
  }

  static void SetUpTestSuite() { WaitForButtonPress(); }

  static void TearDownTestSuite() {
    PrintAllResults();
    WaitForButtonPress();
  }

  void Bench(std::string name, std::function<void(int)> fn) {
    int measure_rounds = getMeasureRounds();
    auto start = std::chrono::steady_clock::now();
    fn(measure_rounds);
    auto finish = std::chrono::steady_clock::now();
    auto t = std::chrono::duration_cast<us>(finish - start);
    PrintResult(name, t);
    StoreResult(name, t);
  }

  static void StoreResult(std::string name, us time) {
    time /= getMeasureRounds();
    results_.push_back({name, time});
  }

  static void PrintAllResults() {
    for (const auto &[k, v] : results_) {
      std::cerr << k << ",";
    }
    std::cerr << std::endl;
    for (const auto &[k, v] : results_) {
      std::cerr << v.count() << ",";
    }
    std::cerr << std::endl;
  }
};

std::vector<std::pair<const std::string, us>> ThreadingTest::results_({});

TEST_F(ThreadingTest, GetPid) { Bench("GetPid", BenchGetPid); }

TEST_F(ThreadingTest, SpawnJoin) { Bench("SpawnJoin", BenchSpawnJoin); }

TEST_F(ThreadingTest, UncontendedMutex) {
  Bench("UncontendedMutex", BenchUncontendedMutex);
}

TEST_F(ThreadingTest, Yield) { Bench("Yield", BenchYield); }

TEST_F(ThreadingTest, CondvarPingPong) {
  Bench("CondvarPingPong", BenchCondvarPingPong);
}

TEST_F(ThreadingTest, SemPingPong) { Bench("SemPingPong", BenchSemPingPong); }

TEST_F(ThreadingTest, Pipe) { Bench("Pipe", BenchPipe); }

TEST_F(ThreadingTest, Poll) { Bench("Poll", BenchPoll); }

TEST_F(ThreadingTest, Select) { Bench("Select", BenchSelect); }

TEST_F(ThreadingTest, Mmap) { Bench("Mmap", BenchMMAP); }
