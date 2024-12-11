// seqfile.h - support for files that return fixed sequences of bytes.

#pragma once

#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class SeqFile : public File {
 public:
  SeqFile(unsigned int flags, std::shared_ptr<DirectoryEntry> dent,
          std::string &&output)
      : File(FileType::kNormal, flags, FileMode::kRead, std::move(dent)),
        output_(std::move(output)) {}
  ~SeqFile() = default;

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override {
    if (*off < 0 || static_cast<size_t>(*off) >= output_.size()) return 0;
    size_t to_read = std::min(buf.size(), output_.size() - *off);
    std::memcpy(buf.data(), output_.data() + *off, to_read);
    *off += to_read;
    return to_read;
  }

 private:
  friend cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    save_dent_path(ar);
    ar(output_, cereal::base_class<File>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<SeqFile> &construct) {
    std::string output;
    std::shared_ptr<DirectoryEntry> dent = restore_dent_path(ar);
    ar(output);
    construct(0, std::move(dent), std::move(output));
    ar(cereal::base_class<File>(construct.ptr()));
  }

  const std::string output_;
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::SeqFile);
