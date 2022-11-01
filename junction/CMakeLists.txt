message(STATUS "Building junction")


# Get GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Prepare for tests
enable_testing()
set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)

# Generate shim libraries for tests
add_library(gtest_shim INTERFACE)
target_link_libraries(gtest_shim INTERFACE
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,caladan_shim>"
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

# Generate test configurations
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

# Build all modules
add_subdirectory(base)
add_subdirectory(bindings)
add_subdirectory(filesystem)
add_subdirectory(memorysystem)
add_subdirectory(samples)
add_subdirectory(syscall)
add_subdirectory(kernel)

# Build junction
add_library(junction
  base
  bindings
  filesystem
  memorysystem
  syscall
)

# Configure junction
set_target_properties(junction
  PROPERTIES
    LINKER_LANGUAGE CXX
)
target_link_options(junction PUBLIC
  -Wl,--export-dynamic,--export-dynamic
)
