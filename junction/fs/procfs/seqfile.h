// seqfile.h - support for files that return fixed sequences of bytes.

#pragma once

#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class SeqFile : public File {
 public:
  SeqFile(unsigned int flags, mode_t mode, std::shared_ptr<Inode> ino,
          std::string &&output)
      : File(FileType::kNormal, flags, mode, std::move(ino)),
        output_(std::move(output)) {}
  ~SeqFile() = default;

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override {
    if (*off < 0 || static_cast<size_t>(*off) >= output_.size()) return 0;
    size_t to_read = std::min(buf.size(), output_.size() - *off);
    std::memcpy(buf.data(), output_.data() + *off, to_read);
    *off += to_read;
    return to_read;
  }

  Status<void> Stat(struct stat *statbuf) const override {
    if (get_inode()) return get_inode()->GetStats(statbuf);
    if (!has_stat_) return MakeError(EINVAL);
    *statbuf = stat_;
    return {};
  }

 private:
  friend cereal::access;
  SeqFile(mode_t mode, std::string &&output)
      : File(FileType::kNormal, 0, mode), output_(std::move(output)) {}

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_mode(), output_, cereal::base_class<File>(this));
    if (has_stat_) {
      ar(true, stat_);
      return;
    }

    if (get_inode()) {
      struct stat buf;
      Status<void> ret = get_inode()->GetStats(&buf);
      if (ret) {
        ar(true, buf);
        return;
      }
    }

    ar(false);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<SeqFile> &construct) {
    std::string output;
    mode_t mode;
    ar(mode, output);

    construct(mode, std::move(output));
    SeqFile &f = *construct.ptr();
    ar(cereal::base_class<File>(&f), f.has_stat_);
    if (f.has_stat_) ar(f.stat_);
  }

 private:
  friend cereal::access;

  const std::string output_;
  bool has_stat_{false};
  struct stat stat_;
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::SeqFile);
