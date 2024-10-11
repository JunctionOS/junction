// stdiofile.h - support for STDIN, STDOUT, STDERR

#pragma once

#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

namespace junction {

constexpr int kStdInFileNo = STDIN_FILENO;
constexpr int kStdOutFileNo = STDOUT_FILENO;
constexpr int kStdErrFileNo = STDERR_FILENO;

class StdIOFile : public File {
 public:
  StdIOFile(unsigned int flags, FileMode mode,
            std::shared_ptr<DirectoryEntry> dent);
  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) override;
  Status<void> Stat(struct stat *statbuf) const override;
  Status<void> Sync() override;

 private:
  friend class cereal::access;

  void save(cereal::BinaryOutputArchive &ar) const;
  static void load_and_construct(cereal::BinaryInputArchive &ar,
                                 cereal::construct<StdIOFile> &construct);
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::StdIOFile);
