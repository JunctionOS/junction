#include <csignal>
#include <cstdio>
#include <cstdlib>

int main(int argc, char *argv[]) {
  close(0);
  close(1);
  close(2);

  int magic = 42;
  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  // restored
  if (magic != 42) {
    return EXIT_FAILURE;
  }

  return 0;
}
