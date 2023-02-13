// fake_worker.h - support for carefully controlled fake work generation

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum {
  PGSHIFT_4KB = 12,
  PGSHIFT_2MB = 21,
  PGSHIFT_1GB = 30,
};

enum {
  PGSIZE_4KB = (1 << PGSHIFT_4KB), /* 4096 bytes */
  PGSIZE_2MB = (1 << PGSHIFT_2MB), /* 2097152 bytes */
  PGSIZE_1GB = (1 << PGSHIFT_1GB), /* 1073741824 bytes */
};

/**
 * is_power_of_two - determines if an integer is a power of two
 * @x: the value
 *
 * Returns true if the integer is a power of two.
 */
#define is_power_of_two(x) ((x) != 0 && !((x) & ((x)-1)))

/**
 * align_up - rounds a value up to an alignment
 * @x: the value
 * @align: the alignment (must be power of 2)
 *
 * Returns an aligned value.
 */
#define align_up(x, align)                  \
  ({                                        \
    assert(is_power_of_two(align));         \
    (((x)-1) | ((typeof(x))(align)-1)) + 1; \
  })

class FakeWorker {
 public:
  // Perform n iterations of fake work.
  virtual void Work(uint64_t n) = 0;
};

class SqrtWorker : public FakeWorker {
 public:
  SqrtWorker() {}
  ~SqrtWorker() {}

  // Performs n iterations of sqrt().
  void Work(uint64_t n);
};

class StridedMemtouchWorker : public FakeWorker {
 public:
  ~StridedMemtouchWorker() { delete buf_; }

  // Creates a strided memory touching worker.
  static StridedMemtouchWorker *Create(std::size_t size, size_t stride);

  // Performs n strided memory touches.
  void Work(uint64_t n);

 private:
  StridedMemtouchWorker(char *buf, std::size_t size, size_t stride)
      : buf_(buf), size_(size), stride_(stride) {}

  volatile char *buf_;
  std::size_t size_;
  std::size_t stride_;
};

class MemStreamWorker : public FakeWorker {
 public:
  ~MemStreamWorker();

  // Creates a memory streaming worker.
  static MemStreamWorker *Create(std::size_t size);

  // Performs n memory reads.
  void Work(uint64_t n);

 private:
  MemStreamWorker(char *buf, std::size_t size) : buf_(buf), size_(size) {}

  volatile char *buf_;
  std::size_t size_;
};

class RandomMemtouchWorker : public FakeWorker {
 public:
  ~RandomMemtouchWorker() { delete buf_; }

  // Creates a random memory touching worker.
  static RandomMemtouchWorker *Create(std::size_t size, unsigned int seed);

  // Performs n random memory touches.
  void Work(uint64_t n);

 private:
  RandomMemtouchWorker(char *buf, std::vector<unsigned int> schedule)
      : buf_(buf), schedule_(std::move(schedule)) {}

  volatile char *buf_;
  std::vector<unsigned int> schedule_;
};

// Parses a string to generate one of the above fake workers.
FakeWorker *FakeWorkerFactory(std::string s);
