#pragma once

#include "cereal/archives/binary.hpp"
#include "cereal/types/base_class.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/polymorphic.hpp"
#include "cereal/types/vector.hpp"
#include "dumb.h"

class Table {
 public:
  void push(std::shared_ptr<DummyData> dat) { tab_.push_back(std::move(dat)); }

  void test() const {
    for (auto const &dat : tab_) {
      dat->test();
    }
  }

  template <class Archive>
  void serialize(Archive &ar) {
    ar(tab_);
  }

 private:
  std::vector<std::shared_ptr<DummyData>> tab_;
};

std::shared_ptr<DummyData> create_smart(int num, int fd);
