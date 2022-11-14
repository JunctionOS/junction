// elf.h - ELF object file loader

#pragma once

#include <optional>
#include <string_view>

#include "junction/base/error.h"

namespace junction {

// elf_data contains metadata about a succesfully loaded ELF file.
struct elf_data {
  struct interp_data {
    uintptr_t base_addr;   // the interpreter's base address
    uintptr_t entry_addr;  // the interpreter's entry address
  };

  uintptr_t entry_addr;  // the program's entry address
  uintptr_t phdr_addr;   // the program's PHDR table address
  size_t phdr_num;       // the number of PHDR entries in the table
  size_t phdr_entsz;     // the size of each PHDR entry

  // optional interpreter data (set if intrepeter is in use)
  std::optional<interp_data> interp;
};

// Load an ELF object file into memory. Returns metadata if successful.
Status<elf_data> LoadELF(std::string_view path);

}  // namespace junction
