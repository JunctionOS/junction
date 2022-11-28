#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

extern "C" {
#include <semaphore.h>
}

#include <gtest/gtest.h>

using us = std::chrono::duration<double, std::micro>;
constexpr int kMeasureRounds = 1000000;

void BenchSpawnJoin() {
  for (int i = 0; i < kMeasureRounds; ++i) {
    auto th = std::thread([]() { ; });
    th.join();
  }
}

void BenchUncontendedMutex() {
  std::mutex m;
  volatile unsigned long foo = 0;

  for (int i = 0; i < kMeasureRounds; ++i) {
    std::unique_lock<std::mutex> l(m);
    foo++;
  }
}

void BenchYield() {
  auto th = std::thread([]() {
    for (int i = 0; i < kMeasureRounds / 2; ++i) std::this_thread::yield();
  });

  for (int i = 0; i < kMeasureRounds / 2; ++i) std::this_thread::yield();

  th.join();
}

void BenchSemPingPong() {
  sem_t sem1, sem2;
  if (sem_init(&sem1, 0, 0)) assert(false);
  if (sem_init(&sem2, 0, 1)) assert(false);

  auto th = std::thread([&]() {
    for (int i = 0; i < kMeasureRounds / 2; ++i) {
      sem_wait(&sem1);
      sem_post(&sem2);
    }
  });

  for (int i = 0; i < kMeasureRounds / 2; ++i) {
    sem_wait(&sem2);
    sem_post(&sem1);
  }

  th.join();
  sem_destroy(&sem1);
  sem_destroy(&sem2);
}

void BenchCondvarPingPong() {
  std::mutex m;
  std::condition_variable cv;
  bool dir = false;  // shared and protected by @m.

  auto th = std::thread([&]() {
    std::unique_lock<std::mutex> l(m);
    for (int i = 0; i < kMeasureRounds / 2; ++i) {
      while (dir) cv.wait(l);
      dir = true;
      cv.notify_one();
    }
  });

  std::unique_lock<std::mutex> l(m);
  for (int i = 0; i < kMeasureRounds / 2; ++i) {
    while (!dir) cv.wait(l);
    dir = false;
    cv.notify_one();
  }

  th.join();
}

void PrintResult(std::string name, us time) {
  time /= kMeasureRounds;
  std::cout << "test '" << name << "' took " << time.count() << " us."
            << std::endl;
}

void Bench(std::string name, std::function<void()> fn) {
  auto start = std::chrono::steady_clock::now();
  fn();
  auto finish = std::chrono::steady_clock::now();
  PrintResult(name, std::chrono::duration_cast<us>(finish - start));
}

class ThreadingTest : public ::testing::Test {};

TEST_F(ThreadingTest, SpawnJoin) {
  Bench("SpawnJoin", [] { BenchSpawnJoin(); });
}

TEST_F(ThreadingTest, UncontendedMutex) {
  Bench("UncontendedMutex", [] { BenchUncontendedMutex(); });
}

TEST_F(ThreadingTest, Yield) {
  Bench("Yield", [] { BenchYield(); });
}

TEST_F(ThreadingTest, CondvarPingPong) {
  Bench("CondvarPingPong", [] { BenchCondvarPingPong(); });
}

TEST_F(ThreadingTest, SemPingPong) {
  Bench("SemPingPong", [] { BenchSemPingPong(); });
}
