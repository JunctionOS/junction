message(STATUS "Building junction filesystem")

add_library(fs
  core.cc
  dev.cc
  file.cc
  linuxfs/dir.cc
  linuxfs/linuxfile.cc
  linuxfs/linuxfs.cc
  memfs/memfs.cc
  memfs/dir.cc
  procfs/procfs.cc
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
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -- $<TARGET_FILE:memfs_test>"
)
endif()
