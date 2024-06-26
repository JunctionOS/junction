// dev.c - character and block device support

#include "junction/fs/dev.h"

#include <algorithm>
#include <map>

#include "junction/base/arch.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"

namespace junction {

namespace {

template <Status<size_t> (*Reader)(std::span<std::byte>, bool),
          Status<size_t> (*Writer)(std::span<const std::byte>)>
class SpecialFile : public File {
 public:
  SpecialFile(unsigned int flags, FileMode mode,
              std::shared_ptr<Inode> ino) noexcept
      : File(FileType::kSpecial, flags, mode, std::move(ino)) {}
  ~SpecialFile() override = default;

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    return Reader(buf, !is_nonblocking());
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    return Writer(buf);
  }
};

//
// /dev/null
//

Status<size_t> CDevReadNull(std::span<std::byte> buf, bool blocking) {
  return 0;
}
Status<size_t> CDevWriteNull(std::span<const std::byte> buf) {
  return buf.size();
}
using CDevNullFile = SpecialFile<CDevReadNull, CDevWriteNull>;

//
// /dev/zero
//

Status<size_t> CDevReadZeroes(std::span<std::byte> buf, bool blocking) {
  std::fill(buf.begin(), buf.end(), std::byte{0});
  return buf.size();
}
using CDevZeroFile = SpecialFile<CDevReadZeroes, CDevWriteNull>;

//
// /dev/random
//

Status<size_t> CDevReadRandom(std::span<std::byte> buf, bool blocking) {
  return ReadEntropy(buf, blocking);
}
using CDevRandomFile = SpecialFile<CDevReadRandom, CDevWriteNull>;

//
// /dev/urandom
//

Status<size_t> CDevReadURandom(std::span<std::byte> buf, bool blocking) {
  return ReadRandom(buf);
}
using CDevURandomFile = SpecialFile<CDevReadURandom, CDevWriteNull>;

//
// Character device support
//

template <typename T>
  requires(std::derived_from<T, File>)
std::shared_ptr<File> MakeFile(unsigned int flags, FileMode mode,
                               std::shared_ptr<Inode> ino) {
  return std::make_shared<T>(flags, mode, std::move(ino));
}

using FactoryPtr = std::shared_ptr<File> (*)(unsigned int flags, FileMode mode,
                                             std::shared_ptr<Inode> ino);

// Table of supported character devices
const std::map<dev_t, FactoryPtr> CharacterDevices{
    {MakeDevice(1, 3), MakeFile<CDevNullFile>},
    {MakeDevice(1, 5), MakeFile<CDevZeroFile>},
    {MakeDevice(1, 8), MakeFile<CDevRandomFile>},
    {MakeDevice(1, 9), MakeFile<CDevURandomFile>},
};

}  // namespace

Status<std::shared_ptr<File>> DeviceOpen(Inode &ino, dev_t dev,
                                         unsigned int flags, FileMode mode) {
  // Only character devices supported so far.
  if (ino.get_type() != kTypeCharacter) return MakeError(ENODEV);

  // Check if we support this type of device.
  auto it = CharacterDevices.find(dev);
  if (it == CharacterDevices.end()) return MakeError(ENODEV);

  // Create the file.
  return it->second(flags, mode, ino.get_this());
}

}  // namespace junction
