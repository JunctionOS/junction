// mm.h - metadata for memory map

#pragma once

extern "C" {
#include "lib/caladan/runtime/defs.h"
}

#include <span>
#include <string>

#include "junction/base/error.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

class VMAreaMetadata {
 public:
  void Serialize(Snapshotter &s) const & {
    constant_.Serialize(s);
    variable_.Serialize(s);
  }
  size_t SerializedSize() const & {
    return constant_.SerializedSize() + variable_.SerializedSize();
  }

  void SetEnd(uintptr_t end) { constant_.SetEnd(end); }
  void SetOffset(off_t offset) { constant_.SetOffset(offset); }
  void SetFlags(int flags) { constant_.SetFlags(flags); }
  void SetType(uint8_t type) { constant_.SetType(type); }
  void SetFilename(std::string filename) {
    constant_.SetFilename(filename);
    variable_.SetFilename(filename);
  }

  Status<void> DeserializeConstant(std::span<const std::byte> serialized) {
    if (serialized.size() != sizeof(ConstantVMAreaMetadata)) {
      return MakeError(EINVAL);
    }
    memcpy(&this->constant_, serialized.data(), sizeof(ConstantVMAreaMetadata));
    return {};
  }
  Status<void> DeserializeVariable(std::span<const std::byte> serialized) {
    if (serialized.size() < this->constant_.filename_sz_) {
      return MakeError(EINVAL);
    }
    if (this->constant_.file_backed_) {
      this->variable_.SetFilename(
          std::string(reinterpret_cast<char const *>(serialized.data()),
                      serialized.size()));
    }
    return {};
  }

  static Status<VMAreaMetadata> FromBytes(
      std::span<const std::byte> serialized) {
    VMAreaMetadata vma_m;
    auto const &constant = vma_m.DeserializeConstant(
        serialized.subspan(0, sizeof(ConstantVMAreaMetadata)));
    if (unlikely(!constant)) {
      return MakeError(constant);
    }

    auto const &variable = vma_m.DeserializeVariable(
        serialized.subspan(sizeof(ConstantVMAreaMetadata),
                           serialized.size() - sizeof(ConstantVMAreaMetadata)));
    if (unlikely(!variable)) {
      return MakeError(variable);
    }

    return vma_m;
  }

  uintptr_t GetEnd() const & { return constant_.GetEnd(); }
  off_t GetOffset() const & { return constant_.GetOffset(); }
  int GetFlags() const & { return constant_.GetFlags(); }
  uint8_t GetType() const & { return constant_.GetType(); }
  std::optional<std::string_view> GetFilename() const & {
    if (this->constant_.HasFilename()) {
      return this->variable_.GetFilename();
    }

    return {};
  }

 private:
#pragma pack(push, 1)
  class ConstantVMAreaMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      s.MetadataPush(
          {reinterpret_cast<std::byte const *>(this), SerializedSize()});
    }
    size_t SerializedSize() const & { return sizeof(ConstantVMAreaMetadata); }

    void SetEnd(uintptr_t end) { end_ = end; }
    void SetOffset(off_t offset) { offset_ = offset; }
    void SetFlags(int flags) { flags_ = flags; }
    void SetFilename(std::string const &filename) {
      file_backed_ = true;
      filename_sz_ = filename.size();
    }
    void SetType(uint8_t type) { type_ = type; }

    uintptr_t GetEnd() const & { return end_; }
    off_t GetOffset() const & { return offset_; }
    int GetFlags() const & { return flags_; }
    uint8_t GetType() const & { return type_; }
    bool HasFilename() const & { return file_backed_; }

   private:
    friend VMAreaMetadata;
    uintptr_t end_;
    off_t offset_;
    int flags_;
    uint8_t type_;
    bool file_backed_{false};
    size_t filename_sz_{0};
  };
#pragma pack(pop)
  class VariableLengthVMAreaMetadata {
   public:
    void Serialize(Snapshotter &s) const & {
      s.MetadataPush(
          std::as_bytes(std::span{filename_.data(), filename_.size()}));
    }
    size_t SerializedSize() const & { return filename_.size(); }
    void SetFilename(std::string filename) { filename_ = filename; }

    std::string_view GetFilename() const & { return filename_; }

   private:
    std::string filename_;
  };

  ConstantVMAreaMetadata constant_;
  VariableLengthVMAreaMetadata variable_;
};

}  // namespace junction
