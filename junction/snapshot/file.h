// file.h - metadata for files

#pragma once

extern "C" {
#include "lib/caladan/runtime/defs.h"
}

#include <span>
#include <string>

#include "junction/base/error.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

class FileMetadata {
 public:
  void Serialize(Snapshotter &s) const & {
    constant_.Serialize(s);
    variable_.Serialize(s);
  }
  size_t SerializedSize() const & {
    return constant_.SerializedSize() + variable_.SerializedSize();
  }

  void SetType(int type) { constant_.SetType(type); }
  void SetFlags(unsigned int flags) { constant_.SetFlags(flags); }
  void SetMode(unsigned int mode) { constant_.SetMode(mode); }
  void SetOffset(off_t offset) { constant_.SetOffset(offset); }
  void SetFd(int fd) { constant_.SetFd(fd); }
  void SetFilename(std::string filename) {
    constant_.SetFilename(filename);
    variable_.SetFilename(filename);
  }

  Status<void> DeserializeConstant(std::span<const std::byte> serialized) {
    if (serialized.size() != sizeof(ConstantFileMetadata)) {
      return MakeError(EINVAL);
    }
    memcpy(&this->constant_, serialized.data(), sizeof(ConstantFileMetadata));
    return {};
  }
  Status<void> DeserializeVariable(std::span<const std::byte> serialized) {
    if (serialized.size() < this->constant_.filename_sz_) {
      return MakeError(EINVAL);
    }
    if (this->constant_.has_filename_) {
      this->variable_.SetFilename(
          std::string(reinterpret_cast<char const *>(serialized.data()),
                      serialized.size()));
    }
    return {};
  }
  static Status<FileMetadata> FromBytes(std::span<const std::byte> serialized) {
    FileMetadata fm;
    auto const &constant = fm.DeserializeConstant(
        serialized.subspan(0, sizeof(ConstantFileMetadata)));
    if (unlikely(!constant)) {
      return MakeError(constant);
    }

    auto const &variable = fm.DeserializeVariable(
        serialized.subspan(sizeof(ConstantFileMetadata),
                           serialized.size() - sizeof(ConstantFileMetadata)));
    if (unlikely(!variable)) {
      return MakeError(variable);
    }

    return fm;
  }

  int GetType() const & { return constant_.GetType(); }
  unsigned int GetFlags() const & { return constant_.GetFlags(); }
  unsigned int GetMode() const & { return constant_.GetMode(); }
  off_t GetOffset() const & { return constant_.GetOffset(); }
  int GetFd() const & { return constant_.GetFd(); }
  std::optional<std::string_view> GetFilename() const & {
    if (constant_.HasFilename()) {
      return variable_.GetFilename();
    }

    return {};
  }

 private:
#pragma pack(push, 1)
  class ConstantFileMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      s.MetadataPush(
          {reinterpret_cast<std::byte const *>(this), SerializedSize()});
    }
    size_t SerializedSize() const & { return sizeof(ConstantFileMetadata); }

    void SetType(int type) { type_ = type; }
    void SetFlags(unsigned int flags) { flags_ = flags; }
    void SetMode(unsigned int mode) { mode_ = mode; }
    void SetOffset(off_t offset) { offset_ = offset; }
    void SetFd(int fd) { fd_ = fd; }
    void SetFilename(std::string const &filename) {
      has_filename_ = true;
      filename_sz_ = filename.size();
    }

    int GetType() const & { return type_; }
    unsigned int GetFlags() const & { return flags_; }
    unsigned int GetMode() const & { return mode_; }
    off_t GetOffset() const & { return offset_; }
    int GetFd() const & { return fd_; }
    bool HasFilename() const & { return has_filename_; }

   private:
    friend FileMetadata;
    int type_;
    unsigned int flags_;
    unsigned int mode_;
    off_t offset_;
    int fd_;

    bool poll_source_set_up_{false};

    bool has_filename_{false};
    size_t filename_sz_{0};
  };
#pragma pack(pop)
  class VariableLengthFileMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      return s.MetadataPush(
          std::as_bytes(std::span{filename_.data(), filename_.size()}));
    }
    size_t SerializedSize() const & { return filename_.size(); }
    void SetFilename(std::string filename) { filename_ = filename; }
    std::string_view GetFilename() const & { return filename_; }

   private:
    std::string filename_;
  };

  ConstantFileMetadata constant_;
  VariableLengthFileMetadata variable_;
};

}  // namespace junction
