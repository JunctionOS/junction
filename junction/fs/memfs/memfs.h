// defs.h - internal definitions for memfs

#include "junction/fs/dev.h"
#include "junction/fs/fs.h"

namespace junction {

namespace memfs {

// Generate file attributes. Does not set st_size.
struct stat MemInodeToAttributes(const Inode &ino) {
  struct stat s = InodeToAttributes(ino);
  s.st_blksize = kPageSize;
  s.st_dev = MakeDevice(8, 0);  // fake SCSI device
  return s;
}

// Create a soft link inode.
std::shared_ptr<ISoftLink> MemCreateISoftLink(std::string_view path,
                                              ino_t inum);
// Create a character or block device inode.
std::shared_ptr<Inode> MemCreateIDevice(dev_t dev, mode_t mode, ino_t inum);

}  // namespace memfs

}  // namespace junction
