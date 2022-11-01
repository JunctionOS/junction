message(STATUS "Building junction filesystem")

# Library
add_library(filesystem
  file.cpp
  filesystem.cpp
)

target_link_libraries(filesystem
  base
  bindings
)

# Tests
add_executable(filesystem_test
  filesystem_test.cpp
)

target_link_libraries(filesystem_test
  filesystem
  gtest_shim
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test.txt "foo")

add_test(
  NAME filesystem_test
  COMMAND sh -c "$<TARGET_FILE:filesystem_test> ${caladan_test_config_path}"
)