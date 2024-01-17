#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <csignal>
#include <cstdlib>

#include "snapshot_sys.h"

const char *elf_filename = "/tmp/entrypoint.elf";
const char *metadata_filename = "/tmp/entrypoint.metadata";

int main(int argc, char *argv[]) {
  const char *elf;
  const char *metadata;
  elf = elf_filename;
  metadata = metadata_filename;

  printf("Hello, world!\n");

  if (argc > 2) {
    elf = argv[2];
    metadata = argv[1];
    auto r = snapshot(elf, metadata);

    if (r == 0) {
      printf("snapshotted!\n");
    } else if (r == 1) {
      printf("restored!\n");
    } else {
      printf("snapshot/restore failed :-(\n");
      return -1;
    }
  }
    
  return 0;
}
