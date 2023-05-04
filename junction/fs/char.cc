#include <algorithm>

#include "junction/kernel/file.h"

namespace junction {

template <Status<size_t> (*Reader)(std::span<std::byte>),
          Status<size_t> (*Writer)(std::span<const std::byte>)>
class SpecialFile : public File {
 public:
  SpecialFile() noexcept : File(FileType::kSpecial, 0, kModeReadWrite) {}
  ~SpecialFile() override = default;

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    return Reader(buf);
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    return Writer(buf);
  }
};

Status<size_t> ReadNull(std::span<std::byte> buf) { return 0; }

Status<size_t> WriteNull(std::span<const std::byte> buf) { return buf.size(); }

using NullFile = SpecialFile<ReadNull, WriteNull>;

Status<size_t> ReadZeroes(std::span<std::byte> buf) {
  std::fill(buf.begin(), buf.end(), std::byte{0});
  return buf.size();
}

using ZeroFile = SpecialFile<ReadZeroes, WriteNull>;

}  // namespace junction
