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
  linuxfile_test.cpp
)

target_link_libraries(filesystem_test
  syscall
  filesystem
  gtest_shim
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test.txt "foo")

add_test(
  NAME filesystem_test
  COMMAND sh -c "$<TARGET_FILE:filesystem_test> ${caladan_test_config_path}"
)
