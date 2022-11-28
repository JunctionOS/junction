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

set(CUSTOM_GLIBC_DIR
  "${CMAKE_SOURCE_DIR}/lib/glibc/build/"
)

set(CUSTOM_GLIBC_INTERPRETER_PATH
  "${CUSTOM_GLIBC_DIR}/elf/ld.so"
)

if(EXISTS ${CUSTOM_GLIBC_INTERPRETER_PATH})
  message("Setting custom ld.so interpreter to ${CUSTOM_GLIBC_INTERPRETER_PATH}")
  add_compile_definitions(CUSTOM_GLIBC_INTERPRETER_PATH=\"${CUSTOM_GLIBC_INTERPRETER_PATH}\")
  add_compile_definitions(CUSTOM_GLIBC_DIR=\"${CUSTOM_GLIBC_DIR}\")
  add_compile_definitions(CUSTOM_GLIBC_PRELOAD=\"$<TARGET_FILE:shim_preload>\")
else()
  message("Missing custom ld.so interpreter and libc.so")
endif()

# Build all modules
add_subdirectory(base)
add_subdirectory(bindings)
add_subdirectory(filesystem)
add_subdirectory(syscall)
add_subdirectory(kernel)
add_subdirectory(samples)
add_subdirectory(shim)

# Build junction
add_library(junction
  junction.cc
)
target_link_libraries(junction INTERFACE
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,syscall>"
  base
  bindings
  filesystem
  kernel
  glibc_shim_backend
)

add_executable(junction_run
  run.cc
)

target_link_libraries(junction_run
  junction
)
