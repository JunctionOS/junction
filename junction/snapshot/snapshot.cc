#include <cstdio>

extern "C" {
#include <fcntl.h>
}

#include "junction/base/error.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

/// Open Helpers

Status<Snapshotter> Snapshotter::Open(uint64_t entry_addr,
                                      std::vector<elf_phdr> pheaders,
                                      std::string_view elf_path,
                                      std::string_view metadata_path) {
  auto elf_file = KernelFile::Open(elf_path, O_CREAT | O_TRUNC | O_WRONLY,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (unlikely(!elf_file)) {
    return MakeError(elf_file);
  }

  auto metadata_file =
      KernelFile::Open(metadata_path, O_CREAT | O_TRUNC | O_WRONLY,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (unlikely(!metadata_file)) {
    return MakeError(metadata_file);
  }

  auto snapshotter =
      Snapshotter(std::move(*elf_file), std::move(*metadata_file));

  // write headers
  elf_header hdr;
  memset(&hdr, 0, sizeof(elf_header));
  hdr.magic[0] = '\177';
  hdr.magic[1] = 'E';
  hdr.magic[2] = 'L';
  hdr.magic[3] = 'F';
  hdr.magic[4] = kMagicClass64;
  hdr.magic[5] = kMagicData2LSB;
  hdr.magic[6] = kMagicVersion;
  hdr.type = kETypeExec;
  hdr.machine = kMachineAMD64;
  hdr.version = static_cast<uint32_t>(kMagicVersion);
  hdr.entry = entry_addr;
  hdr.phoff = sizeof(elf_header);
  hdr.shoff = 0;
  hdr.flags = 0;
  hdr.ehsize = sizeof(elf_header);
  hdr.phsize = sizeof(elf_phdr);
  hdr.phnum = pheaders.size();
  hdr.shsize = 0;
  hdr.shnum = 0;
  hdr.shstrndx = 0;

  std::vector<iovec> headers;
  size_t const header_size =
      sizeof(elf_header) + pheaders.size() * sizeof(elf_phdr);
  bool const needs_padding = header_size < AlignUp(header_size, 4096);
  headers.reserve(pheaders.size() + 1 + (needs_padding) ? 1 : 0);

  std::array<std::byte, 4096> padding{std::byte{0}};
  iovec const iov = {.iov_base = reinterpret_cast<std::byte *>(&hdr),
                     .iov_len = sizeof(elf_header)};
  headers.push_back(iov);
  for (auto &pheader : pheaders) {
    iovec const iov = {.iov_base = reinterpret_cast<std::byte *>(&pheader),
                       .iov_len = sizeof(elf_phdr)};
    headers.push_back(iov);
  }

  if (needs_padding) {
    size_t padding_len = AlignUp(header_size, 4096) - header_size;
    iovec const iov = {.iov_base = padding.data(), .iov_len = padding_len};
    headers.push_back(iov);
  }

  auto ret = snapshotter.ElfWritev(std::span(headers));
  if (unlikely(!ret)) {
    return MakeError(ret);
  }

  return snapshotter;
}

/// Low Level Helpers

Status<size_t> Snapshotter::ElfWritev(std::span<const iovec> iov) & {
  size_t expected_write_size = 0;
  for (auto const &vec : iov) {
    expected_write_size += vec.iov_len;
  }
  auto const &ret = this->elf_.Writev(iov);
  if (unlikely(!ret)) {
    return ret;
  } else if (*ret != expected_write_size) {
    return MakeError(-1);
  }

  return ret;
}

Status<size_t> Snapshotter::MetadataFlush() & {
  size_t expected_write_size = 0;
  for (auto const &vec : serialized_metadata_) {
    expected_write_size += vec.iov_len;
  }
  auto const &ret = this->metadata_.Writev(std::span(serialized_metadata_));
  if (unlikely(!ret)) {
    return ret;
  } else if (*ret != expected_write_size) {
    return MakeError(-1);
  }

  return ret;
}

void Snapshotter::MetadataPush(std::span<const std::byte> buf) & {
  iovec const v = {.iov_base = (void *)buf.data(), .iov_len = buf.size()};
  serialized_metadata_.push_back(v);
}

}  // namespace junction
