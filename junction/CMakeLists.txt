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

# The worst case of this config is:
# - 2 hyperthreads for caladan's iokernel
# - Half the remaining hyperthreads for a client proc
# - Half the remaining hyperthreads for a server proc

# this detects the number of hyperthreads
execute_process(COMMAND nproc OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE n_hyperthreads)
# remove the 2 hyperthreads dedicated to the iokernel and half
math(EXPR max_available_threads "(${n_hyperthreads} - 2) / 2")

# Cap the number of kthreads at 10
math(EXPR cap "10")
execute_process(COMMAND printf "%d\n%d\n" ${max_available_threads} ${cap}
    COMMAND sort -n
    COMMAND head -n 1
    OUTPUT_STRIP_TRAILING_WHITESPACE
    OUTPUT_VARIABLE
    n_kthreads
)

# Generate test configurations
set(caladan_test_config
"host_addr 192.168.127.7
host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads ${n_kthreads}
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 0
runtime_priority lc
runtime_quantum_us 0"
)
set(caladan_test_config_path
  ${CMAKE_CURRENT_BINARY_DIR}/caladan_test.config
)
file(WRITE ${caladan_test_config_path} ${caladan_test_config})

set(caladan_test_config_st
"host_addr 192.168.127.7
host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads 1
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 0
runtime_priority lc
runtime_quantum_us 0"
)
file(WRITE  ${CMAKE_CURRENT_BINARY_DIR}/caladan_test_st.config ${caladan_test_config_st})

set(caladan_test_config_ts
"host_addr 192.168.127.7
host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads ${n_kthreads}
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 0
runtime_priority lc
runtime_quantum_us 10"
)
file(WRITE  ${CMAKE_CURRENT_BINARY_DIR}/caladan_test_ts.config ${caladan_test_config_ts})

set(caladan_test_config_ts_st
"host_addr 192.168.127.7
host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads 1
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 0
runtime_priority lc
runtime_quantum_us 10"
)
file(WRITE  ${CMAKE_CURRENT_BINARY_DIR}/caladan_test_ts_st.config ${caladan_test_config_ts_st})


set(fs_test_config
"/memfs
/tmp
/usr/local
/var/logs
/var/lib"
)
set(fs_test_config_path
  ${CMAKE_CURRENT_BINARY_DIR}/test.filesystem.config
)
file(WRITE ${fs_test_config_path} ${fs_test_config})

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


if(PERMISSIVE_SECCOMP)
  add_compile_definitions(PERMISSIVE_SECCOMP="1")
endif()

if (WRITEABLE_LINUX_FS)
  add_compile_definitions(WRITEABLE_LINUX_FS="1")
endif()

# Build all modules
add_subdirectory(base)
add_subdirectory(bindings)
add_subdirectory(control)
add_subdirectory(fs)
add_subdirectory(kernel)
add_subdirectory(net)
add_subdirectory(samples)
add_subdirectory(shim)
add_subdirectory(snapshot)
add_subdirectory(syscall)

# Build junction
add_library(junction
  junction.cc
  libc_override.cc
  new_override.cc
)
target_link_libraries(junction INTERFACE
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,syscall>"
  base
  fs
  net
  kernel
  glibc_shim_backend
  bindings
  boost_program_options
)

add_executable(junction_run
  run.cc
)

target_link_libraries(junction_run
  junction
  flatbuffers
)
