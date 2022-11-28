message(STATUS "Building junction filesystem")

# Library
add_library(filesystem
  linuxfile.cc
  linuxfs.cc
)

target_link_libraries(filesystem
  base
  bindings
  kernel
)

# Tests
add_executable(filesystem_test
  fs_testenv.cc
  linuxfile_test.cc
  linuxfs_test.cc
)

target_link_libraries(filesystem_test
  junction
  gtest_shim
)

# Test inputs
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test.txt "foo")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test1.txt "foo")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/a/b/c/d/test.txt "foo")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/a/b/c/e/test.txt "foo")

add_test(
  NAME filesystem_test
  COMMAND sh -c "$<TARGET_FILE:filesystem_test> ${caladan_test_config_path}"
)
