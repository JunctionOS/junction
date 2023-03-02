message(STATUS "Building junction filesystem")

# Library
add_library(filesystem
  vfs.cc
  linuxfile.cc
  linuxfs.cc
  memfsfile.cc
  memfs.cc
)

target_link_libraries(filesystem
  base
  bindings
  kernel
)

# Tests
add_executable(filesystem_test
  memfs_test.cc
)
target_link_libraries(filesystem_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

# Test inputs
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test.txt "foo")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test1.txt "foo")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/a/b/c/d/test.txt "foo")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/a/b/c/e/test.txt "foo")

add_test(
  NAME filesystem_test_junction
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -- $<TARGET_FILE:filesystem_test>"
)
