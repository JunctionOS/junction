#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <csignal>
#include <cstdlib>

#include "snapshot_sys.h"

const char* elf_filename1 = "/tmp/snapshot1.elf";
const char* metadata_filename1 = "/tmp/snapshot1.metadata";

const char* elf_filename2 = "/tmp/snapshot2.elf";
const char* metadata_filename2 = "/tmp/snapshot2.metadata";

int main() {
  auto r1 = snapshot(elf_filename1, metadata_filename1);

  if (r1 == 0) {
    printf("snapshotted once!\n");
  } else if (r1 == 1) {
    printf("restored from the first snapshot!\n");
  } else {
    printf("failure :-(\n");
    return -1;
  }

  auto r2 = snapshot(elf_filename2, metadata_filename2);

  if (r2 == 0) {
    printf("snapshotted twice!\n");
  } else if (r2 == 1) {
    printf("restored from the second snapshot!\n");
  } else {
    printf("failure :-(\n");
    return -1;
  }

  return 0;
}
