#include <cassert>
#include <csignal>
#include <cstdio>
#include <cstdlib>

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);  // make stdout unbuffered
  printf("Hello, world!\n");

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");
  return 0;
}
