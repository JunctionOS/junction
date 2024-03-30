// memfs.h - internal definitions for memfs

#include "junction/fs/dev.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"

namespace junction::memfs {

// Generate file attributes. Does not set st_size.
void MemInodeToStats(const Inode &ino, struct stat *buf) {
  InodeToStats(ino, buf);
  buf->st_blksize = kPageSize;
  buf->st_dev = MakeDevice(8, 0);  // fake SCSI device
}

// Create a soft link inode.
std::shared_ptr<ISoftLink> CreateISoftLink(std::string_view path);
// Create a character or block device inode.
std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode);
// Allocate a unique inode number.
ino_t AllocateInodeNumber();

}  // namespace junction::memfs
