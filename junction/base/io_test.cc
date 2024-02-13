
#include "junction/base/io.h"

#include <gtest/gtest.h>

namespace junction {

inline constexpr size_t kDataSize = 255;
inline constexpr size_t kBufDepth = 4;
inline constexpr size_t kHalfBufDepth = kBufDepth / 2;
inline constexpr size_t kMaxRequestSize = 16;

class MockPipe {
 public:
  Status<size_t> Read(std::span<std::byte> in) {
    size_t rlen = std::min(in.size(), data_.size() - read_pos_);
    if (!rlen) return MakeError(EUNEXPECTEDEOF);
    std::copy_n(data_.begin() + read_pos_, rlen, in.begin());
    read_pos_ += rlen;
    return rlen;
  }

  Status<size_t> Write(std::span<const std::byte> in) {
    std::copy_n(in.begin(), in.size(), std::back_inserter(data_));
    return in.size();
  }

  void Flush() {}

 private:
  std::vector<std::byte> data_;
  size_t read_pos_{0};
};

template <class T>
class StreamBufferReaderWrapper {
 public:
  StreamBufferReaderWrapper(T &io, size_t len) : sbuf_(io, len) {}
  Status<size_t> Read(std::span<std::byte> in) {
    size_t ret = sbuf_.sgetn(reinterpret_cast<char *>(in.data()), in.size());
    if (!ret) return MakeError(EUNEXPECTEDEOF);
    return ret;
  }

 private:
  StreamBufferReader<T> sbuf_;
};

template <class T>
class StreamBufferWriterWrapper {
 public:
  StreamBufferWriterWrapper(T &io, size_t len) : sbuf_(io, len) {}
  Status<size_t> Write(std::span<const std::byte> out) {
    size_t ret =
        sbuf_.sputn(reinterpret_cast<const char *>(out.data()), out.size());
    if (!ret) return MakeError(EUNEXPECTEDEOF);
    return ret;
  }

  void Flush() { sbuf_.pubsync(); }

 private:
  StreamBufferWriter<T> sbuf_;
};

class IOTest : public ::testing::Test {};

template <class IOReaderWriter, class IOReader>
void TestReader(IOReaderWriter &rw, IOReader &r) {
  std::vector<std::byte> test_data_(kDataSize);
  for (size_t i = 0; i < kDataSize; i++)
    test_data_.push_back(std::byte(rand()));

  ASSERT_TRUE(WriteFull(rw, {test_data_.data(), kDataSize}));
  rw.Flush();

  std::vector<std::byte> read_data(kDataSize);
  size_t pos = 0;

  auto pull = [&](size_t nbytes) {
    Status<size_t> ret = r.Read({read_data.data() + pos, nbytes});
    ASSERT_TRUE(ret);
    ASSERT_GT(*ret, 0);
    pos += *ret;
  };

  // Trigger read fast path
  pull(kBufDepth);

  // Trigger fill and subsequent read from buffer
  pull(kHalfBufDepth);
  pull(kHalfBufDepth);

  // Trigger fill and subsequent read with fast path
  pull(kHalfBufDepth);
  pull(kHalfBufDepth + kBufDepth);

  // Read data in random chunk sizes
  while (pos < kDataSize) {
    size_t pull_sz = std::min(1 + (rand() % kMaxRequestSize), kDataSize - pos);
    pull(pull_sz);
  }

  ASSERT_EQ(memcmp(read_data.data(), test_data_.data(), kDataSize), 0);
}

// Tests a writer instance
template <class IOReaderWriter, class IOWriter>
void TestWriter(IOReaderWriter &rw, IOWriter &w) {
  std::vector<std::byte> test_data_(kDataSize);
  for (size_t i = 0; i < kDataSize; i++)
    test_data_.push_back(std::byte(rand()));

  size_t pos = 0;

  auto push = [&](size_t nbytes) {
    auto ret = w.Write({test_data_.data() + pos, nbytes});
    ASSERT_TRUE(ret);
    if constexpr (std::is_same<decltype(ret), Status<size_t>>::value) {
      ASSERT_GT(*ret, 0);
      pos += *ret;
    } else {
      pos += nbytes;
    }
  };

  // fast path
  push(kBufDepth);

  // Partial fill and subsequent write
  push(kHalfBufDepth);
  push(kHalfBufDepth);

  // Partial fill subsequent write with fast path
  push(kHalfBufDepth);
  push(kHalfBufDepth + kBufDepth);

  // Write data in random chunk sizes
  while (pos < kDataSize) {
    size_t write_size =
        std::min(1 + (rand() % kMaxRequestSize), kDataSize - pos);
    push(write_size);
  }

  w.Flush();

  std::vector<std::byte> read_data(kDataSize);
  ASSERT_TRUE(ReadFull(rw, std::span<std::byte>(read_data.data(), kDataSize)));
  ASSERT_EQ(memcmp(read_data.data(), test_data_.data(), kDataSize), 0);
}

TEST_F(IOTest, MockPipeReaderTest) {
  MockPipe f;
  TestReader(f, f);
}

TEST_F(IOTest, MockPipeWriterTest) {
  MockPipe f;
  TestWriter(f, f);
}

TEST_F(IOTest, BufferedReaderTest) {
  MockPipe f;
  BufferedReader<MockPipe> r(f, kBufDepth);
  TestReader(f, r);
}

TEST_F(IOTest, BufferedWriterTest) {
  MockPipe f;
  BufferedWriter<MockPipe> w(f, kBufDepth);
  TestWriter(f, w);
}

TEST_F(IOTest, StreamBufferReaderTest) {
  MockPipe f;
  StreamBufferReaderWrapper<MockPipe> r(f, kBufDepth);
  TestReader(f, r);
}

TEST_F(IOTest, StreamBufferWriterTest) {
  MockPipe f;
  StreamBufferWriterWrapper<MockPipe> w(f, kBufDepth);
  TestWriter(f, w);
}

}  // namespace junction