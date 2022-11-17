message(STATUS "Building junction filesystem")

# Library
add_library(filesystem
  linuxfile.cpp
)

target_link_libraries(filesystem
  base
  bindings
  kernel
)

# Tests
add_executable(filesystem_test
  fs_testenv.cpp
  linuxfile_test.cpp
)

target_link_libraries(filesystem_test
  junction
  gtest_shim
)

# Test inputs
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test.txt "foo")

add_test(
  NAME filesystem_test
  COMMAND sh -c "$<TARGET_FILE:filesystem_test> ${caladan_test_config_path}"
)
