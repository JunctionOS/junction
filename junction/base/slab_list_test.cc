#include "junction/base/slab_list.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

using namespace junction;

class SlabListTest : public ::testing::Test {};

constexpr size_t kBlockSize = 4096;

TEST_F(SlabListTest, CreateSlabListTest) {
  SlabList<kBlockSize> sl_1;
  EXPECT_EQ(sl_1.size(), 0);

  const size_t size = 256;
  SlabList<kBlockSize> sl_2(size);
  EXPECT_EQ(sl_2.size(), size);
}

TEST_F(SlabListTest, SetValuesMultipleBlocksTest) {
  // List of some values to choose from when assigning.
  const std::vector<char> vals({'a', 'b', 'c', 'd', 'e'});
  const size_t size = kBlockSize * 5;

  SlabList<kBlockSize> sl(size);

  // Assign values.
  for (size_t i = 0; i < size; i++) {
    sl[i] = static_cast<std::byte>(vals[i % vals.size()]);
  }

  // Read back assigned values.
  for (size_t i = 0; i < size; i++) {
    EXPECT_EQ(static_cast<char>(sl[i]), vals[i % vals.size()]);
  }
}

TEST_F(SlabListTest, FillTest) {
  const size_t size = kBlockSize * 5;
  const std::byte val = static_cast<std::byte>('x');

  SlabList<kBlockSize> sl(size);

  // Fill values.
  std::fill(sl.begin(), sl.end(), val);

  // Read back filled values.
  for (const std::byte& v : sl) {
    EXPECT_EQ(v, val);
  }
}

TEST_F(SlabListTest, CopyNTest) {
  // Create a vector of bytes and repeatedly write it to the SlabList from an
  // increasing offset. This will require resizing the SlabList and creating
  // more than 1 blocks.
  const size_t size = 104;
  const size_t iters = 50;
  static_assert(static_cast<float>(size * iters) / kBlockSize > 1.0);

  std::vector<std::byte> src(size, static_cast<std::byte>('x'));
  auto off = 0;

  // Copy from src to dst.
  SlabList<kBlockSize> dst;
  for (size_t i = 0; i < iters; i++) {
    if (dst.size() - off < src.size()) {
      dst.Resize(src.size() + off);
    }
    auto it = std::copy_n(src.begin(), src.size(), dst.begin() + off);
    EXPECT_EQ(it, dst.end());
    off += src.size();
  }
}

TEST_F(SlabListTest, ShiftRightTest) {
  // List of some values to choose from when assigning.
  std::vector<char> vals_char({'a', 'b', 'c', 'd', 'e'});
  std::vector<std::byte> vals(vals_char.size());
  for (size_t i = 0; i < vals_char.size(); i++) {
    vals[i] = static_cast<std::byte>(vals_char[i]);
  }

  const size_t size = kBlockSize * 5;
  SlabList<kBlockSize> sl(size);

  // Use this to compare with a std::vector implementation.
  std::vector<std::byte> truth(size);

  const size_t shift_by = 4;

  // Assign values.
  for (size_t i = 0; i < size; i++) {
    sl[i] = vals[i % vals.size()];
    truth[i] = vals[i % vals.size()];
  }

  // Shift.
  std::shift_right(sl.begin(), sl.end(), shift_by);
  std::shift_right(truth.begin(), truth.end(), shift_by);

  // Compare with the same operation performed on std::vector.
  for (size_t i = shift_by; i < size; i++) {
    EXPECT_EQ(sl[i], truth[i]);
  }
}
