// memfs.h - internal definitions for memfs

#include "junction/fs/dev.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"

namespace junction::memfs {

// Generate file attributes. Does not set st_size.
struct stat MemInodeToStats(const Inode &ino) {
  struct stat s = InodeToStats(ino);
  s.st_blksize = kPageSize;
  s.st_dev = MakeDevice(8, 0);  // fake SCSI device
  return s;
}

// Create a soft link inode.
std::shared_ptr<ISoftLink> CreateISoftLink(std::string_view path);
// Create a character or block device inode.
std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode);
// Allocate a unique inode number.
ino_t AllocateInodeNumber();

}  // namespace junction::memfs
