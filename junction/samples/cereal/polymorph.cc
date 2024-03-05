#include "polymorph.h"

#include <fstream>
#include <iostream>
#include <sstream>

int main() {
  {
    Table tab;
    tab.push(std::make_shared<DummyData>(1024));
    tab.push(create_smart(4096, -1));

    std::ofstream dummy_file("test.bin");
    cereal::BinaryOutputArchive archive(dummy_file);

    archive(tab);

    std::cout << "fields before serialization\n";

    tab.test();
  }

  {
    std::ifstream is("test.bin");
    cereal::BinaryInputArchive ar(is);

    Table tab;
    ar(tab);

    std::cout << "fields after deserialization\n";

    tab.test();
  }

  return 0;
}
