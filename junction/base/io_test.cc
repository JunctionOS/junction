
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

bool validate_data(std::span<std::byte> in, uint8_t firstval) {
  unsigned char *p = reinterpret_cast<unsigned char *>(in.data());
  for (size_t i = 0; i < in.size(); i++) {
    if (*p++ != firstval + i) return false;
  }

  return true;
}

template <class IOReaderWriter, class IOReader>
void TestReader(IOReaderWriter &rw, IOReader &r) {
  for (size_t i = 0; i < kDataSize; i++) {
    char b = i;
    rw.Write(writable_span(&b, 1));
  }

  rw.Flush();

  char b[kMaxRequestSize];
  auto spn = readable_span(b, kMaxRequestSize);
  size_t pos = 0;

  // Read fast path
  Status<size_t> ret = r.Read(spn.subspan(0, kBufDepth));
  ASSERT_TRUE(ret && *ret == kBufDepth);
  ASSERT_TRUE(validate_data(spn.subspan(0, kBufDepth), pos));
  pos += kBufDepth;

  // Partial fill and subsequent read
  ret = r.Read(spn.subspan(0, kHalfBufDepth));
  ASSERT_TRUE(ret && *ret == kHalfBufDepth);
  ret = r.Read(spn.subspan(kHalfBufDepth, kHalfBufDepth));
  ASSERT_TRUE(ret && *ret == kHalfBufDepth);
  ASSERT_TRUE(validate_data(spn.subspan(0, kBufDepth), pos));
  pos += kBufDepth;

  // Partial fill subsequent read with fast path
  ret = r.Read(spn.subspan(0, kHalfBufDepth));
  ASSERT_TRUE(ret && *ret == kHalfBufDepth);
  ret = r.Read(spn.subspan(kHalfBufDepth, kHalfBufDepth + kBufDepth));
  ASSERT_TRUE(ret && *ret == kHalfBufDepth + kBufDepth);
  ASSERT_TRUE(validate_data(spn.subspan(0, 2 * kBufDepth), pos));
  pos += 2 * kBufDepth;

  // Read data in random chunk sizes
  while (true) {
    size_t span_sz = 1 + (rand() % kMaxRequestSize);
    ret = r.Read(spn.subspan(0, span_sz));
    if (!ret || *ret == 0) {
      ASSERT_EQ(pos, kDataSize);
      break;
    }
    ASSERT_TRUE(validate_data(spn.subspan(0, *ret), pos));
    pos += *ret;
  }
}

// Tests a writer instance
template <class IOReaderWriter, class IOWriter>
void TestWriter(IOReaderWriter &rw, IOWriter &w) {
  std::vector<std::byte> test_data_;
  test_data_.reserve(kDataSize);
  for (size_t i = 0; i < kDataSize; i++)
    test_data_.push_back(*reinterpret_cast<std::byte *>(&i));

  std::span<std::byte> spn(test_data_.data(), kDataSize);

  size_t pos = 0;
  // fast path
  ASSERT_TRUE(w.Write(spn.subspan(pos, kBufDepth)));
  pos += kBufDepth;

  // Partial fill and subsequent write
  ASSERT_TRUE(w.Write(spn.subspan(pos, kHalfBufDepth)));
  pos += kHalfBufDepth;
  ASSERT_TRUE(w.Write(spn.subspan(pos, kHalfBufDepth)));
  pos += kHalfBufDepth;

  // Partial fill subsequent write with fast path
  ASSERT_TRUE(w.Write(spn.subspan(pos, kHalfBufDepth)));
  pos += kHalfBufDepth;
  ASSERT_TRUE(w.Write(spn.subspan(pos, kHalfBufDepth + kBufDepth)));
  pos += kHalfBufDepth + kBufDepth;

  // Write data in random chunk sizes
  while (pos < kDataSize) {
    size_t write_size =
        std::min(1 + (rand() % kMaxRequestSize), kDataSize - pos);
    ASSERT_TRUE(w.Write(spn.subspan(pos, write_size)));
    pos += write_size;
  }

  w.Flush();

  std::vector<std::byte> read_data;
  read_data.reserve(kDataSize);
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