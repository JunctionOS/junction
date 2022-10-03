message(STATUS "Building junction test")

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

include_directories(
  ${CMAKE_SOURCE_DIR}/inc
)

add_executable(junction_tests
  filesystem_test.cpp
)
target_link_libraries(junction_tests
  junction
  GTest::gtest_main
)

add_custom_target(generate_test_inputs
  COMMAND echo "foo" > ${CMAKE_CURRENT_BINARY_DIR}/test.txt
)

add_dependencies(junction_tests
  generate_test_inputs
)

include(GoogleTest)
gtest_discover_tests(junction_tests)
