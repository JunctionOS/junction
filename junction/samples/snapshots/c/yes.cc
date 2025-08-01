#include <chrono>
#include <cstdio>
#include <thread>

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);  // make stdout unbuffered
  using namespace std::chrono_literals;
  printf("Hello, world!\n");

  int round = 0;
  while (round < 1000) {
    printf("y: %d\n", round++);
    std::this_thread::sleep_for(1000ms);
  }
  return 0;
}
