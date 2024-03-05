#include "polymorph.h"

namespace detail {

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

}  // namespace detail

std::shared_ptr<DummyData> create_smart(int num, int fd) {
  return std::make_shared<detail::SmartData>(num, fd);
}

CEREAL_REGISTER_TYPE(::detail::SmartData);
CEREAL_REGISTER_POLYMORPHIC_RELATION(DummyData, ::detail::SmartData)
