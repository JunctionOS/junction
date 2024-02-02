#include "polymorph.h"

#include <fstream>
#include <iostream>
#include <sstream>

int main() {
  {
    std::shared_ptr<DummyData> p1 = std::make_shared<DummyData>(1024);
    std::shared_ptr<DummyData> p2 = std::make_shared<SmartData>(4096, -1);

    std::ofstream dummy_file("test.bin");
    cereal::BinaryOutputArchive archive(dummy_file);

    archive(p1, p2);

    std::cout << "fields before serialization\n";

    p1->test();
    p2->test();
  }

  {
    std::ifstream is("test.bin");
    cereal::BinaryInputArchive ar(is);

    std::shared_ptr<DummyData> p1;
    std::shared_ptr<DummyData> p2;
    ar(p1, p2);

    std::cout << "fields after deserialization\n";

    p1->test();
    p2->test();
  }

  return 0;
}
