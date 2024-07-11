#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include <atomic>

std::atomic_bool stop = false;
std::atomic_int ctr = 0;

void *func(void *) {
  printf("[from thread]: started\n");
  while (!stop.load()) {
    ctr += 1;
  }
  printf("[from thread]: finished: %d\n", ctr.load());
  return NULL;
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);  // make stdout unbuffered
  printf("hello, world!\n");

  printf("starting thread\n");
  pthread_t th;
  if (pthread_create(&th, NULL, func, NULL) != 0) {
    printf("failed to start the thread\n");
    return -1;
  }

  printf("host started thread\n");

  // Stop and wait for snapshot.
  kill(getpid(), SIGSTOP);

  printf("restored\n");

  stop.store(true);

  printf("send stop\n");

  if (pthread_join(th, NULL) != 0) {
    printf("failed to join the thread\n");
    return -1;
  }

  printf("joined thread\n");

  return 0;
}
