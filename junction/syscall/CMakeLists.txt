message(STATUS "Building junction syscall")


# Outputs syscall_tbl.cpp to build/junction/syscall/syscall_tbl.cpp
add_custom_command(
    OUTPUT  syscall_tbl.cpp
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/systbl.py
      ${CMAKE_CURRENT_SOURCE_DIR}/syscall_defs.txt
      ${CMAKE_CURRENT_SOURCE_DIR}/usys.txt
      ${CMAKE_CURRENT_BINARY_DIR}/syscall_tbl.cpp
    DEPENDS systbl.py syscall_defs.txt systbl.hpp usys.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_library(syscall
  syscall.cpp
  seccomp.cpp
  syscall_tbl.cpp
)

target_link_libraries(syscall
  kernel
  bindings
)

# Benchmarks
# syscall_benchmark_glibc (custom glibc and junction)
add_executable(syscall_benchmark
  syscall_benchmark.cpp
)
target_link_libraries(syscall_benchmark
  junction
)
target_link_options(syscall_benchmark PUBLIC
  ${JUNCTION_GLIBC}
)

# syscall_benchmark_default_glibc (default glibc and junction)
add_executable(syscall_benchmark_default_glibc
  syscall_benchmark.cpp
)
target_link_libraries(syscall_benchmark_default_glibc
  junction
)

# Tests
# dispatch_test
add_executable(dispatch_test
  dispatch_test.cpp
)
target_link_libraries(dispatch_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

add_test(
  NAME dispatch_test_native
  COMMAND sh -c "$<TARGET_FILE:dispatch_test>"
)

add_test(
  NAME dispatch_test_junction
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} $<TARGET_FILE:dispatch_test>"
)
