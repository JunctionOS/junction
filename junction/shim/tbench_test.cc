#include <cassert>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

extern "C" {
#include <fcntl.h>
#include <poll.h>
#include <semaphore.h>
#include <signal.h>
#include <spawn.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
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

  if (measure_rounds % 2 != 0) measure_rounds++;

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

volatile bool delivered[32];

void StackedTestHandler(int signo) { delivered[signo] = true; }

static volatile bool test_delivered;
void SingleTestHandler(int signo) { test_delivered = true; }

void TestRestartSys() {
  test_delivered = false;

  EXPECT_NE(signal(SIGUSR1, SingleTestHandler), SIG_ERR);
  EXPECT_NE(signal(SIGUSR2, SIG_IGN), SIG_ERR);

  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGUSR1);
  sigaddset(&blocked, SIGUSR2);

  EXPECT_EQ(sigprocmask(SIG_BLOCK, &blocked, nullptr), 0);

  sigset_t empty;
  sigemptyset(&empty);

  auto main_tid = gettid();
  auto pid = getpid();

  EXPECT_EQ(tgkill(pid, main_tid, SIGUSR2), 0);

  auto start = std::chrono::steady_clock::now();
  auto th = std::thread([&]() {
    usleep(500);
    EXPECT_EQ(tgkill(pid, main_tid, SIGUSR1), 0);
  });

  int ret = sigsuspend(&empty);
  auto end = std::chrono::steady_clock::now();
  auto usec = std::chrono::duration_cast<us>(end - start).count();

  th.join();

  EXPECT_EQ(test_delivered, true);
  EXPECT_EQ(ret, -1);

  // Note: this test is non-deterministic and may not always work.
  EXPECT_EQ(errno, EINTR);
  EXPECT_GE(usec, 400);

  sigset_t cur_mask;
  sigemptyset(&cur_mask);
  EXPECT_EQ(sigprocmask(0, nullptr, &cur_mask), 0);
  EXPECT_EQ(sigismember(&cur_mask, SIGUSR1), 1);
  EXPECT_EQ(sigismember(&cur_mask, SIGUSR2), 1);
}

void TestOneSignalBlocked() {
  test_delivered = false;

  EXPECT_NE(signal(SIGUSR1, SingleTestHandler), SIG_ERR);

  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);

  EXPECT_EQ(sigprocmask(SIG_BLOCK, &s, nullptr), 0);

  EXPECT_EQ(tgkill(getpid(), gettid(), SIGUSR1), 0);

  sigemptyset(&s);
  EXPECT_EQ(sigpending(&s), 0);
  EXPECT_EQ(sigismember(&s, SIGUSR1), 1);

  EXPECT_EQ(test_delivered, false);

  EXPECT_EQ(sigprocmask(SIG_UNBLOCK, &s, nullptr), 0);

  EXPECT_EQ(test_delivered, true);
}

void TestOneSignalNotBlocked() {
  test_delivered = false;
  EXPECT_NE(signal(SIGUSR1, SingleTestHandler), SIG_ERR);
  EXPECT_EQ(tgkill(getpid(), gettid(), SIGUSR1), 0);
  EXPECT_EQ(test_delivered, true);
}

void TestStackedSignals() {
  EXPECT_NE(signal(SIGUSR1, StackedTestHandler), SIG_ERR);
  EXPECT_NE(signal(SIGUSR2, StackedTestHandler), SIG_ERR);

  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  sigaddset(&s, SIGUSR2);

  EXPECT_EQ(sigprocmask(SIG_BLOCK, &s, nullptr), 0);

  EXPECT_EQ(tgkill(getpid(), gettid(), SIGUSR1), 0);

  sigemptyset(&s);
  EXPECT_EQ(sigpending(&s), 0);
  EXPECT_EQ(sigismember(&s, SIGUSR1), 1);

  EXPECT_EQ(tgkill(getpid(), gettid(), SIGUSR2), 0);

  sigemptyset(&s);
  EXPECT_EQ(sigpending(&s), 0);
  EXPECT_EQ(sigismember(&s, SIGUSR1), 1);
  EXPECT_EQ(sigismember(&s, SIGUSR2), 1);

  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  sigaddset(&s, SIGUSR2);

  EXPECT_EQ(delivered[SIGUSR1], false);
  EXPECT_EQ(delivered[SIGUSR2], false);

  EXPECT_EQ(sigprocmask(SIG_UNBLOCK, &s, nullptr), 0);

  EXPECT_EQ(delivered[SIGUSR1], true);
  EXPECT_EQ(delivered[SIGUSR2], true);
}

volatile int vals[2];

void SigHandler(int signo) {
  int valno = signo == SIGUSR1 ? 0 : 1;
  vals[valno] = vals[valno] + 1;
}

void BenchSignalPingPongSigSuspend(int measure_rounds) {
  EXPECT_NE(signal(SIGUSR1, SigHandler), SIG_ERR);
  EXPECT_NE(signal(SIGUSR2, SigHandler), SIG_ERR);

  pid_t mypid = getpid();

  pid_t t1 = gettid();
  volatile pid_t t2 = 0;

  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  sigaddset(&s, SIGUSR2);

  sigset_t s1;
  sigfillset(&s1);
  sigdelset(&s1, SIGUSR1);
  sigdelset(&s1, SIGUSR2);

  auto th = std::thread([&]() {
    t2 = gettid();
    EXPECT_EQ(sigprocmask(SIG_BLOCK, &s, nullptr), 0);
    for (int i = 0; i < measure_rounds / 2; ++i) {
      EXPECT_EQ(tgkill(mypid, t1, SIGUSR1), 0) << std::strerror(errno);

      // Wait for flag
      while (vals[1] == i) sigsuspend(&s1);
    }
    while (t2) sched_yield();
  });

  EXPECT_EQ(sigprocmask(SIG_BLOCK, &s, nullptr), 0);

  while (!t2)
    ;

  for (int i = 0; i < measure_rounds / 2; ++i) {
    // Wait for flag
    while (vals[0] == i) sigsuspend(&s1);

    // send signal
    EXPECT_EQ(tgkill(mypid, t2, SIGUSR2), 0) << std::strerror(errno);
  }

  t2 = 0;

  th.join();
}

void BenchSignalPingPongSpin(int measure_rounds) {
  EXPECT_NE(signal(SIGUSR1, SigHandler), SIG_ERR);
  EXPECT_NE(signal(SIGUSR2, SigHandler), SIG_ERR);

  pid_t mypid = getpid();

  pid_t t1 = gettid();
  volatile pid_t t2;

  auto th = std::thread([&]() {
    t2 = gettid();

    for (int i = 0; i < measure_rounds / 2; ++i) {
      EXPECT_EQ(tgkill(mypid, t1, SIGUSR1), 0) << std::strerror(errno);

      // Wait for flag
      while (vals[1] == i)
        ;
    }
  });

  for (int i = 0; i < measure_rounds / 2; ++i) {
    // Wait for flag
    while (vals[0] == i)
      ;

    // send signal
    EXPECT_EQ(tgkill(mypid, t2, SIGUSR2), 0) << std::strerror(errno);
  }

  th.join();
}

void BenchEventFdPingPong(int measure_rounds) {
  int efd1 = eventfd(0, 0);
  EXPECT_GE(efd1, 0);

  int efd2 = eventfd(0, 0);
  EXPECT_GE(efd2, 0);

  auto th = std::thread([&]() {
    uint64_t val = UINT64_MAX;
    for (int i = 0; i < measure_rounds / 2; ++i) {
      ssize_t rret = read(efd1, &val, sizeof(val));
      EXPECT_EQ(rret, 8);
      EXPECT_EQ(val, i + 1);

      ssize_t wret = write(efd2, &val, sizeof(val));
      EXPECT_EQ(wret, 8);
    }
  });

  uint64_t val;
  for (int i = 0; i < measure_rounds / 2; ++i) {
    val = i + 1;
    ssize_t wret = write(efd1, &val, sizeof(val));
    EXPECT_EQ(wret, 8);

    val = UINT64_MAX;
    ssize_t rret = read(efd2, &val, sizeof(val));
    EXPECT_EQ(rret, 8);
    EXPECT_EQ(val, i + 1);
  }

  th.join();
  close(efd1);
  close(efd2);
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

void TestKill() {
  pid_t child;
  const char *const args[] = {"/bin/sleep", "10", NULL};
  extern char **environ;

  auto start = std::chrono::steady_clock::now();
  auto ret = posix_spawn(&child, args[0], nullptr, nullptr,
                         const_cast<char *const *>(args), environ);
  EXPECT_EQ(ret, 0);

  errno = 0;
  EXPECT_EQ(kill(child, SIGKILL), 0);
  EXPECT_EQ(errno, 0);
  EXPECT_EQ(child, waitpid(child, nullptr, 0));
  auto end = std::chrono::steady_clock::now();
  auto usec = std::chrono::duration_cast<us>(end - start).count();

  // If kill() does not work, we expect to see a 10 second delay.
  // Otherwise, this test should run quickly. Pick 1 second as the upper bound,
  // though if the test is interrupt for > 1s this test may fail.
  EXPECT_LE(usec, 1000000);
}

void BenchPosixSpawn(int measure_rounds) {
  for (int i = 0; i < measure_rounds; i++) {
    int pipefds[2];
    int pipefds_parent_to_child[2];
    int ret = pipe(pipefds);
    EXPECT_EQ(ret, 0);

    ret = pipe(pipefds_parent_to_child);
    EXPECT_EQ(ret, 0);

    posix_spawn_file_actions_t file_actions;
    ret = posix_spawn_file_actions_init(&file_actions);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_adddup2(&file_actions,
                                           pipefds_parent_to_child[0], 0);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_adddup2(&file_actions, pipefds[1], 2);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_addclose(&file_actions, pipefds[1]);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_addclose(&file_actions, pipefds[0]);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_addclose(&file_actions,
                                            pipefds_parent_to_child[1]);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_addclose(&file_actions,
                                            pipefds_parent_to_child[0]);
    EXPECT_EQ(ret, 0);

    pid_t child;
    const char *const args[2] = {POSIX_SPAWN_CHILD_BIN, nullptr};
    extern char **environ;
    ret = posix_spawn(&child, args[0], &file_actions, nullptr,
                      const_cast<char *const *>(args), environ);
    EXPECT_EQ(ret, 0);

    ret = posix_spawn_file_actions_destroy(&file_actions);
    EXPECT_EQ(ret, 0);

    close(pipefds[1]);
    close(pipefds_parent_to_child[0]);

    int wstatus;

    EXPECT_EQ(kill(child, SIGSTOP), 0);
    EXPECT_EQ(child, waitpid(child, &wstatus, WUNTRACED));
    EXPECT_TRUE(WIFSTOPPED(wstatus));
    EXPECT_EQ(kill(child, SIGCONT), 0);

    char b;
    EXPECT_EQ(write(pipefds_parent_to_child[1], &b, 1), 1);

    EXPECT_EQ(child, waitpid(child, &wstatus, 0));
    EXPECT_TRUE(WIFEXITED(wstatus));

    size_t bytes_read = 0;
    std::string expected = "in child process\n";
    char buf[expected.size() + 1];
    while (bytes_read < expected.size()) {
      ssize_t rret = read(pipefds[0], buf, expected.size() - bytes_read);
      EXPECT_GT(rret, 0);
      bytes_read += rret;
    }
    buf[expected.size()] = '\0';
    EXPECT_EQ(std::string(buf), expected);
    close(pipefds[0]);
  }
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
        if (n < 0) printf("ret is %d\n", errno);
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
    int maxfd = *std::max_element(fds.begin(), fds.end()) + 1;
    int ret = select(maxfd, &rfds, nullptr, nullptr, nullptr);
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

void BenchEPoll(int measure_rounds) {
  static constexpr size_t kBufSize = 64;
  static constexpr size_t kPollThreads = 100;
  size_t bytes_to_write = kBufSize * measure_rounds / kPollThreads;
  std::vector<int> pfds(kPollThreads);

  for (size_t i = 0; i < kPollThreads; i++) {
    int pipefds[2];
    int ret = pipe2(pipefds, O_NONBLOCK);
    EXPECT_EQ(ret, 0);
    pfds[i] = pipefds[0];

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

  // create the epoll file and set up a poll set
  int epfd = epoll_create1(0);
  EXPECT_GE(epfd, 0);
  for (int fd : pfds) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = fd;
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    EXPECT_EQ(ret, 0);
  }

  // wait for events and process them
  char buf[kBufSize];
  struct epoll_event events[kPollThreads];
  size_t open_count = kPollThreads;
  while (open_count > 0) {
    int nfds = epoll_wait(epfd, events, kPollThreads, -1);
    for (int i = 0; i < nfds; ++i) {
      int fd = events[i].data.u64;
      if (events[i].events & EPOLLIN) {
        ssize_t n = read(fd, buf, kBufSize);
        EXPECT_GT(n, 0);
        continue;
      }
      if (events[i].events & EPOLLHUP) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        open_count--;
      }
    }
  }
  close(epfd);
}

void TestKernelSignalCatch() {
  static void *kernel_sig_test_page;
  constexpr size_t kTestPageSize = 4096;
  constexpr size_t kTestVal = 25;

  auto f = [](int signo, siginfo_t *si, void *c) {
    EXPECT_EQ(si->si_addr, kernel_sig_test_page);
    EXPECT_EQ(
        mprotect(kernel_sig_test_page, kTestPageSize, PROT_READ | PROT_WRITE),
        0);
    *reinterpret_cast<uint64_t *>(kernel_sig_test_page) = kTestVal;
  };

  struct sigaction act, oact;
  act.sa_sigaction = f;
  act.sa_flags = SA_SIGINFO;
  sigemptyset(&act.sa_mask);

  kernel_sig_test_page = mmap(nullptr, kTestPageSize, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(kernel_sig_test_page, MAP_FAILED);

  ASSERT_EQ(sigaction(SIGSEGV, &act, &oact), 0);
  EXPECT_EQ(*reinterpret_cast<uint64_t *>(kernel_sig_test_page), kTestVal);
  EXPECT_EQ(sigaction(SIGSEGV, &oact, nullptr), 0);

  EXPECT_EQ(munmap(kernel_sig_test_page, kTestPageSize), 0);
}

void BenchGetTime(int measure_rounds) {
  struct timespec ts;
  for (int i = 0; i < measure_rounds; ++i) {
    std::ignore = clock_gettime(CLOCK_MONOTONIC, &ts);
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
    if (env_str != "1" && env_str != "true" && env_str != "True") return;

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

#if 1
TEST_F(ThreadingTest, TestPosixSpawn) { BenchPosixSpawn(10); }
#endif

TEST_F(ThreadingTest, GetPid) { Bench("GetPid", BenchGetPid); }

TEST_F(ThreadingTest, SpawnJoin) { Bench("SpawnJoin", BenchSpawnJoin); }

TEST_F(ThreadingTest, RestartSystemCall) { TestRestartSys(); }
TEST_F(ThreadingTest, SignalBlocked) { TestOneSignalBlocked(); }
TEST_F(ThreadingTest, SignalNotBlocked) { TestOneSignalNotBlocked(); }

TEST_F(ThreadingTest, StackedSignals) { TestStackedSignals(); }
TEST_F(ThreadingTest, TestKill) { TestKill(); }
TEST_F(ThreadingTest, KernelSignalCatch) { TestKernelSignalCatch(); };

TEST_F(ThreadingTest, SignalPingPongSpin) {
  Bench("SignalPingPongSpin", BenchSignalPingPongSpin);
}

TEST_F(ThreadingTest, SignalPingPongSuspend) {
  Bench("SignalPingPongSuspend", BenchSignalPingPongSigSuspend);
}

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

TEST_F(ThreadingTest, EPoll) { Bench("EPoll", BenchEPoll); }

TEST_F(ThreadingTest, Mmap) { Bench("Mmap", BenchMMAP); }

TEST_F(ThreadingTest, EventFd) {
  Bench("EventFdPingPong", BenchEventFdPingPong);
}

TEST_F(ThreadingTest, GetTime) { Bench("GetTime", BenchGetTime); }
