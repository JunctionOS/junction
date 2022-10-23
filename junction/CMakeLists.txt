message(STATUS "Building junction jnct")

include(FindPkgConfig)

pkg_check_modules(CAPSTONE REQUIRED capstone)
find_package(Threads REQUIRED)

include_directories(
  ${CMAKE_SOURCE_DIR}/lib/syscall_intercept/install/include
  ${CMAKE_SOURCE_DIR}/lib/shenango/inc
  ${CMAKE_SOURCE_DIR}
)

add_library(junction
  base/error.cc
  base/io.cc

  bindings/runtime.cc
  bindings/thread.cc

#  syscall/handlers.cpp
#  syscall/intercept.c

#  filesystem/file.cpp
#  filesystem/filesystem.cpp

#  memorysystem/memorysystem.cpp
)

target_link_libraries(junction
  ${CAPSTONE_LIBRARIES}
  ${CMAKE_DL_LIBS}
  Threads::Threads
)

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

set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)

add_executable(junction_tests
  filesystem/filesystem_test.cpp
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
