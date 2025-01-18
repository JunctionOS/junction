message(STATUS "Building junction filesystem")

add_library(fs
  advisory_lock.cc
  core.cc
  dev.cc
  eventfd.cc
  file.cc
  linuxfs/dir.cc
  linuxfs/linuxfile.cc
  linuxfs/linuxfs.cc
  memfs/memfs.cc
  memfs/dir.cc
  pipe.cc
  poll.cc
  procfs/procfs.cc
  stdiofile.cc
)

target_link_libraries(fs
  base
  bindings
  kernel
)

# Tests
add_executable(memfs_test
  memfs/memfs_test.cc
)
target_link_libraries(memfs_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

if (WRITEABLE_LINUX_FS)
else()
add_test(
  NAME memfs_test_junction
  COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS -- $<TARGET_FILE:memfs_test>"
)
endif()
