// dev.h - character and block device support

#pragma once

extern "C" {
#include <sys/stat.h>
}

#include <memory>

#include "junction/base/error.h"
#include "junction/fs/file.h"

namespace junction {

inline constexpr size_t kMinorShift = 20;
inline constexpr dev_t kMinorMask = ((1U << kMinorShift) - 1);
constexpr dev_t DeviceMajor(dev_t dev) { return dev >> kMinorShift; }
constexpr dev_t DeviceMinor(dev_t dev) { return dev & kMinorMask; }
constexpr dev_t MakeDevice(dev_t major, dev_t minor) {
  return major << kMinorShift | minor;
}

// DeviceOpen creates a special file for the inode's device number.
Status<std::shared_ptr<File>> DeviceOpen(std::shared_ptr<DirectoryEntry> dent,
                                         dev_t dev, unsigned int flags,
                                         FileMode mode);

}  // namespace junction
