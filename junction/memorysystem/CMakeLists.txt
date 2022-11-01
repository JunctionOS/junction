message(STATUS "Building junction memorysystem")

# Library
add_library(memorysystem
  memorysystem.cpp
)

target_link_libraries(memorysystem
  base
  bindings
)

# Tests
add_executable(memorysystem_test
  memorysystem_test.cpp
)

target_link_libraries(memorysystem_test
  memorysystem
  gtest_shim
)

add_test(
  NAME memorysystem_test
  COMMAND sh -c "$<TARGET_FILE:memorysystem_test> ${caladan_test_config_path}"
)