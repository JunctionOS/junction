#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

extern "C" {
#include <semaphore.h>
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

  std::cerr << "Measure rounds: " << measure_rounds << std::endl;

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

void PrintResult(std::string name, us time) {
  time /= getMeasureRounds();
  std::cout << "test '" << name << "' took " << time.count() << " us."
            << std::endl;
}

void Bench(std::string name, std::function<void(int)> fn) {
  int measure_rounds = getMeasureRounds();
  auto start = std::chrono::steady_clock::now();
  fn(measure_rounds);
  auto finish = std::chrono::steady_clock::now();
  PrintResult(name, std::chrono::duration_cast<us>(finish - start));
}

class ThreadingTest : public ::testing::Test {};

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
