#include "cereal/archives/binary.hpp"
#include "cereal/types/base_class.hpp"
#include "cereal/types/polymorphic.hpp"

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

class SmartData : public DummyData {
 public:
  SmartData() : DummyData(0), fd_(0) {}
  SmartData(int num, int fd) : DummyData(num), fd_(fd) {}

  template <class Archive>
  void serialize(Archive &ar) {
    ar(cereal::base_class<DummyData>(this), fd_);
  }

  virtual void test() {
    std::cout << "SmartData:\n";
    std::cout << "num=" << this->get_num() << std::endl;
    std::cout << "fd=" << fd_ << std::endl;
  }

 private:
  int fd_;
};

CEREAL_REGISTER_TYPE(SmartData);
CEREAL_REGISTER_POLYMORPHIC_RELATION(DummyData, SmartData)
