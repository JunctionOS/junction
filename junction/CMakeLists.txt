message(STATUS "Building junction jnct")

add_subdirectory(base)
add_subdirectory(bindings)
add_subdirectory(kernel)

include(FindPkgConfig)

pkg_check_modules(CAPSTONE REQUIRED capstone)
find_package(Threads REQUIRED)

include_directories(
  ${CMAKE_SOURCE_DIR}/lib/syscall_intercept/install/include
)

add_library(junction

#  syscall/handlers.cpp
#  syscall/intercept.c

   filesystem/file.cpp
#  filesystem/filesystem.cpp

#  memorysystem/memorysystem.cpp
)

target_link_libraries(junction
  ${CAPSTONE_LIBRARIES}
  ${CMAKE_DL_LIBS}
  Threads::Threads
  base
  bindings
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

add_library(gtest_shim INTERFACE)
target_link_libraries(gtest_shim INTERFACE
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,caladan_shim>"
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

target_link_libraries(junction_tests
  junction
  gtest_shim
)

set(caladan_test_config
"host_addr 192.168.127.7
host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads 2
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 2
runtime_priority lc
host_mac 02:02:02:02:02:02
static_arp 192.168.127.3 02:02:02:02:02:02
runtime_quantum_us 0"
)

set(caladan_test_config_path
  ${CMAKE_CURRENT_BINARY_DIR}/caladan_test.config
)

file(WRITE ${caladan_test_config_path} ${caladan_test_config})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test.txt "foo")

add_test(
  NAME junction_tests
  COMMAND sh -c "$<TARGET_FILE:junction_tests> ${caladan_test_config_path}"
)
