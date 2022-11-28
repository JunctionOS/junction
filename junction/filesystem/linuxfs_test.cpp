#include "junction/filesystem/linuxfs.hpp"

extern "C" {
#include <fcntl.h>
}

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"

using namespace junction;

class LinuxFileSystemTest : public ::testing::Test {};

TEST_F(LinuxFileSystemTest, FileOpenTest) {
  // Inputs/Outputs
  const std::string filepath = "testdata/test.txt";
  const unsigned int flags = 0;
  const unsigned int mode = kModeRead;

  // Prepare
  auto manifest = std::make_shared<LinuxFileSystemManifest>();
  manifest->Insert(filepath, flags);
  LinuxFileSystem fs(manifest);

  // Action
  Status<std::shared_ptr<File>> ret = fs.Open(filepath, mode, flags);

  // Test
  EXPECT_TRUE(ret);

  // Logging
  LOG(DEBUG) << "\n" << fs;
}

TEST_F(LinuxFileSystemTest, FileCreateTest) {
  // Inputs/Outputs
  const std::string filepath = "testdata/noexist.txt";
  const unsigned int flags = kFlagCreate | kModeReadWrite;
  const unsigned int mode = kModeReadWrite | S_IRWXU | S_IRWXG | S_IRWXO;

  // Action
  LinuxFileSystem fs;
  Status<std::shared_ptr<File>> ret_1 = fs.Open(filepath, mode, flags);

  // Test
  EXPECT_TRUE(ret_1);

  // Logging
  LOG(DEBUG) << "\n" << fs;

  // Action (Attempt to open the physical file)
  int open_ret = ksys_open(filepath.c_str(), 0 /* flags */, O_RDWR);

  // Test (The filepath specified must not exist in that directory)
  EXPECT_EQ(-ENOENT, open_ret);

  // Action (Attempt to open the file using the junction filesystem)
  Status<std::shared_ptr<File>> ret_2 =
      fs.Open(filepath, kModeReadWrite, 0 /* flags */);

  // Logging
  LOG(DEBUG) << "\n" << fs;

  // Test (The junction filesystem should be able to open the file)
  EXPECT_TRUE(ret_2);

  // Inputs/Outputs
  std::shared_ptr<File> f = *ret_2;
  const std::string data = "foobar";
  const size_t nbytes = data.size();

  off_t offset{0};

  // Action (Write)
  auto write_ret = f->Write(writable_span(data.c_str(), nbytes), &offset);

  // Test
  EXPECT_TRUE(write_ret);
  EXPECT_EQ(nbytes, write_ret.value());

  // Inputs/Outputs
  auto read_buf = std::make_unique<char[]>(nbytes);
  offset = 0;

  // Action (Read)
  auto read_ret = f->Read(readable_span(read_buf.get(), nbytes), &offset);

  // Test
  EXPECT_TRUE(read_ret);
  EXPECT_EQ(nbytes, read_ret.value());
  EXPECT_EQ(nbytes, offset);
  EXPECT_EQ(data, std::string(read_buf.get(), nbytes));
  EXPECT_EQ(nbytes, offset);
}

TEST_F(LinuxFileSystemTest, MultipleDirectoriesTest) {
  // Inputs/Outputs
  const std::vector<std::string> filepaths(
      {"testdata/a/b/c/d/test.txt", "testdata/a/b/c/e/test.txt"});
  const unsigned int flags = 0;
  const unsigned int mode = kModeRead;

  // Prepare
  auto manifest = std::make_shared<LinuxFileSystemManifest>();
  for (const std::string& filepath : filepaths) {
    manifest->Insert(filepath, flags);
  }
  LinuxFileSystem fs(manifest);

  // Action
  for (const std::string& filepath : filepaths) {
    Status<std::shared_ptr<File>> ret = fs.Open(filepath, mode, flags);
    // Test
    EXPECT_TRUE(ret);
  }

  // Logging
  LOG(DEBUG) << "\n" << fs;
}

class LinuxFileInodeTest : public ::testing::Test {};

TEST_F(LinuxFileInodeTest, InodeFileOpenWithPathnameTest) {
  // Inputs/Outputs
  const std::string filepath = "testdata/test.txt";
  const unsigned int flags = 0;
  const unsigned int mode = kModeRead;
  const unsigned int file_type = kTypeRegularFile;

  // Action
  LinuxFileInode inode(filepath, file_type);
  std::shared_ptr<File> file = inode.Open(filepath, mode, flags);
  const unsigned int type = inode.get_type();

  // Test
  EXPECT_NE(nullptr, file);
  EXPECT_EQ(file_type, type);

  // Logging
  LOG(DEBUG) << "\n" << inode;
}

TEST_F(LinuxFileInodeTest, InodeInsertTest) {
  // Inputs/Outputs
  const unsigned int dir_type = kTypeDirectory;
  const unsigned int file_type = kTypeRegularFile;
  std::shared_ptr<LinuxFileInode> dir =
      std::make_shared<LinuxFileInode>("testdata", dir_type);

  // Action
  // testdata/a
  std::shared_ptr<LinuxFileInode> inode_a =
      std::make_shared<LinuxFileInode>("a", dir_type);
  auto ret = dir->Insert("a", inode_a);

  // Test
  EXPECT_TRUE(ret);

  // Action
  // testdata/a/b
  std::shared_ptr<LinuxFileInode> inode_b =
      std::make_shared<LinuxFileInode>("b", dir_type);
  ret = inode_a->Insert("b", inode_b);

  // Test
  EXPECT_TRUE(ret);

  // Action
  // testdata/a/b/c
  std::shared_ptr<LinuxFileInode> inode_c =
      std::make_shared<LinuxFileInode>("c", dir_type);
  ret = inode_b->Insert("c", inode_c);

  // Test
  EXPECT_TRUE(ret);

  // Action
  // testdata/a/b/d
  std::shared_ptr<LinuxFileInode> inode_d =
      std::make_shared<LinuxFileInode>("d", dir_type);
  ret = inode_b->Insert("d", inode_d);

  // Test
  EXPECT_TRUE(ret);

  // Action
  // testdata/a/b/d/foo.txt
  std::shared_ptr<LinuxFileInode> inode_foo =
      std::make_shared<LinuxFileInode>("foo", file_type);
  ret = inode_d->Insert("foo", inode_foo);

  // Test
  EXPECT_TRUE(ret);

  // Logging
  LOG(DEBUG) << "\n" << *dir;
}

TEST_F(LinuxFileInodeTest, InodeLookupTest) {
  // Inputs/Outputs
  const unsigned int dir_type = kTypeDirectory;
  const unsigned int file_type = kTypeRegularFile;
  std::shared_ptr<LinuxFileInode> dir =
      std::make_shared<LinuxFileInode>("testdata", dir_type);

  // testdata/a
  std::shared_ptr<LinuxFileInode> inode_a =
      std::make_shared<LinuxFileInode>("a", dir_type);
  auto ret = dir->Insert("a", inode_a);
  // testdata/a/b
  std::shared_ptr<LinuxFileInode> inode_b =
      std::make_shared<LinuxFileInode>("b", dir_type);
  ret = inode_a->Insert("b", inode_b);
  // testdata/a/b/c
  std::shared_ptr<LinuxFileInode> inode_c =
      std::make_shared<LinuxFileInode>("c", dir_type);
  ret = inode_b->Insert("c", inode_c);
  // testdata/a/b/d
  std::shared_ptr<LinuxFileInode> inode_d =
      std::make_shared<LinuxFileInode>("d", dir_type);
  ret = inode_b->Insert("d", inode_d);
  // testdata/a/b/d/foo.txt
  std::shared_ptr<LinuxFileInode> inode_foo =
      std::make_shared<LinuxFileInode>("foo", file_type);
  ret = inode_d->Insert("foo", inode_foo);

  // Action
  std::shared_ptr<LinuxFileInode> inode =
      std::dynamic_pointer_cast<LinuxFileInode>(dir->Lookup("a"));

  // Test
  EXPECT_NE(nullptr, inode);
  EXPECT_EQ("a", inode->get_name());
  EXPECT_EQ(dir_type, inode->get_type());

  // Action
  inode = std::dynamic_pointer_cast<LinuxFileInode>(dir->Lookup("b"));

  // Test
  EXPECT_EQ(nullptr, inode);

  // Action
  inode = std::dynamic_pointer_cast<LinuxFileInode>(inode_d->Lookup("foo"));

  // Test
  EXPECT_NE(nullptr, inode);
  EXPECT_EQ("foo", inode->get_name());
  EXPECT_EQ(file_type, inode->get_type());

  // Logging
  LOG(DEBUG) << "\n" << *dir;
}

TEST_F(LinuxFileSystemTest, OpenPageMapTest) {
  // Inputs/Outputs
  const std::string filepath = "/proc/self/pagemap";
  const unsigned int flags = 0;
  const unsigned int mode = kModeRead;

  // Prepare
  auto manifest = std::make_shared<LinuxFileSystemManifest>();
  manifest->Insert(filepath, flags);
  LinuxFileSystem fs(manifest);

  // Action
  Status<std::shared_ptr<File>> ret = fs.Open(filepath, mode, flags);

  // Test
  EXPECT_TRUE(ret);

  // Logging
  LOG(DEBUG) << "\n" << fs;
}
