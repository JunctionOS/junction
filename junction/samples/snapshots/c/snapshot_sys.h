#pragma once

// Magic number
constexpr unsigned long SYS_snapshot = 455;

long snapshot(char const* elf_filename, char const* metadata_filename) {
  long ret;
  asm("movq %1, %%rax;"
      "movq %2, %%rdi;"
      "movq %3, %%rsi;"
      "syscall;"
      "movq %%rax, %0;"
      : "=r"(ret)
      : "r"(SYS_snapshot), "r"(elf_filename), "r"(metadata_filename)
      : "%rax", "%rdi", "%rsi");
  return ret;
}
