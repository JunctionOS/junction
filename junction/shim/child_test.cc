
#include <stdio.h>
#include <unistd.h>

int main() {
  // TODO: add some tests to make sure things are setup properly

  // Block until parent writes to our STDIN (gives it time to test job control
  // signals.)
  char b;
  read(0, &b, 1);

  fprintf(stderr, "in child process\n");
  return 0;
}
