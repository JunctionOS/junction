#pragma once

#include "cereal/archives/binary.hpp"
#include "cereal/types/base_class.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/polymorphic.hpp"
#include "cereal/types/vector.hpp"

class DummyData {
 public:
  DummyData() : num_(0) {}
  DummyData(int num) : num_(num) {}

  template <class Archive>
  void serialize(Archive &ar) {
    ar(num_);
  }

  virtual void test() {
    std::cout << "DummyData:\n";
    std::cout << "num=" << num_ << std::endl;
  }

  int get_num() { return num_; }

 private:
  int num_;
};
