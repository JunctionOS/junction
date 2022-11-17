#include "junction/filesystem/linuxfs.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "junction/bindings/log.h"
#include "junction/kernel/file.h"

using namespace junction;

class LinuxFileSystemTest : public ::testing::Test {};

TEST_F(LinuxFileSystemTest, FileCreationTest) {
  // Inputs/Outputs
  const std::string filepath = "testdata/test.txt";
  const unsigned int flags = kFlagSync;
  const unsigned int mode = kModeRead;

  // Action
  LinuxFileSystem fs;
  Status<std::shared_ptr<File>> file = fs.Open(filepath, mode, flags);

  // Test
  EXPECT_TRUE(file);

  // Logging
  LOG(DEBUG) << "\n" << fs;
}

TEST_F(LinuxFileSystemTest, MultipleDirectoriesTest) {
  // Inputs/Outputs
  const std::vector<std::string> filepaths(
      {"testdata/a/b/c/d/test.txt", "testdata/a/b/c/e/test.txt"});
  const unsigned int flags = kFlagSync;
  const unsigned int mode = kModeRead;

  // Action
  LinuxFileSystem fs;
  for (const std::string& filepath : filepaths) {
    Status<std::shared_ptr<File>> file = fs.Open(filepath, mode, flags);
    // Test
    EXPECT_TRUE(file);
  }

  // Logging
  LOG(DEBUG) << "\n" << fs;
}

class LinuxFileInodeTest : public ::testing::Test {};

TEST_F(LinuxFileInodeTest, InodeFileOpenWithPathnameTest) {
  // Inputs/Outputs
  const std::string filepath = "testdata/test.txt";
  const unsigned int flags = kFlagSync;
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
