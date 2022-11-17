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

# Paths for linking with custom glibc.
# Binaries that need this will set the option JUNCTION_GLIBC.
set(JUNCTION_LIB_PATH
  ${CMAKE_BINARY_DIR}/src
)
# set(GLIBC_BUILD_PATH
#   ${CMAKE_SOURCE_DIR}/lib/glibc/build
# )
# set(OPT_RPATH
#   "-Wl,-rpath,.,-rpath,${JUNCTION_LIB_PATH},-rpath,${CMAKE_CURRENT_BINARY_DIR},-rpath,${GLIBC_BUILD_PATH},-rpath,${GLIBC_BUILD_PATH}/elf,-rpath,${GLIBC_BUILD_PATH}/dlfcn,-rpath,${GLIBC_BUILD_PATH}/nss,-rpath,${GLIBC_BUILD_PATH}/nis,-rpath,${GLIBC_BUILD_PATH}/rt,-rpath,${GLIBC_BUILD_PATH}/resolv,-rpath,${GLIBC_BUILD_PATH}/mathvec,-rpath,${GLIBC_BUILD_PATH}/support,-rpath,${GLIBC_BUILD_PATH}/crypt,-rpath,${GLIBC_BUILD_PATH}/nptl,-rpath,/usr/lib/x86_64-linux-gnu,-rpath,/lib/x86_64-linux-gnu,-rpath,/lib64"
# )
# set(OPT_DYNAMIC_LINKER_PATH
#   "-Wl,--dynamic-linker=${GLIBC_BUILD_PATH}/elf/ld.so"
# )
# set(JUNCTION_GLIBC
#   "${OPT_RPATH} ${OPT_DYNAMIC_LINKER_PATH}"
# )

# Build all modules
add_subdirectory(base)
add_subdirectory(bindings)
add_subdirectory(filesystem)
add_subdirectory(syscall)
add_subdirectory(kernel)
add_subdirectory(samples)

# Build junction
add_library(junction
  junction.cpp
)
target_link_libraries(junction INTERFACE
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,caladan_shim>"
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,syscall>"
  base
  bindings
  filesystem
  kernel
)

# Configure junction
set_target_properties(junction
  PROPERTIES
    LINKER_LANGUAGE CXX
)
target_link_options(junction INTERFACE
  -Wl,--export-dynamic,--export-dynamic
)
