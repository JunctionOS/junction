#include "junction/base/slab_list.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <iostream>
#include <vector>

using namespace junction;

class SlabListTest : public ::testing::Test {};

constexpr size_t kBlockSize = 4096;
constexpr size_t kMaxBlocks = 128;

TEST_F(SlabListTest, CreateSlabListTest) {
  SlabList<kBlockSize, kMaxBlocks> sl_1;
  EXPECT_EQ(sl_1.size(), 0);

  const size_t size = 256;
  SlabList<kBlockSize, kMaxBlocks> sl_2(size);
  EXPECT_EQ(sl_2.size(), size);
}

TEST_F(SlabListTest, SetValuesMultipleBlocksTest) {
  // List of some values to choose from when assigning.
  const std::vector<char> vals({'a', 'b', 'c', 'd', 'e'});

  const size_t size = kBlockSize * 5;
  SlabList<kBlockSize, kMaxBlocks> sl(size);

  // Assign values.
  for (size_t i = 0; i < size; i++) {
    sl[i] = vals[i % vals.size()];
  }

  // Read back assigned values.
  for (size_t i = 0; i < size; i++) {
    EXPECT_EQ(sl[i], vals[i % vals.size()]);
  }
}

TEST_F(SlabListTest, FillTest) {
  const size_t size = kBlockSize * 5;
  const char val = 'x';
  SlabList<kBlockSize, kMaxBlocks> sl(size);

  // Fill values.
  std::fill(sl.begin(), sl.end(), val);

  // Read back filled values.
  for (const char& v : sl) {
    EXPECT_EQ(v, val);
  }
}

TEST_F(SlabListTest, ShiftRightTest) {
  // List of some values to choose from when assigning.
  const std::vector<char> vals({'a', 'b', 'c', 'd', 'e'});
  const size_t size = kBlockSize * 5;
  SlabList<kBlockSize, kMaxBlocks> sl(size);

  // Use this to compare with a std::vector implementation.
  std::vector<char> truth(size);

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
