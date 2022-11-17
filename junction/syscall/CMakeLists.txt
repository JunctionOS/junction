message(STATUS "Building junction syscall")

add_library(syscall
  dispatch.cpp
  glibc.cpp
  seccomp.cpp
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
# dispatch_test (custom glibc and junction)
add_executable(dispatch_test
  syscall_testenv.cpp
  dispatch_test.cpp
)
target_link_libraries(dispatch_test
  junction
  gtest_shim
)
target_link_options(dispatch_test PUBLIC
  ${JUNCTION_GLIBC}
)
target_compile_definitions(dispatch_test PUBLIC
  JUNCTION
)
add_test(
  NAME dispatch_test
  COMMAND sh -c "$<TARGET_FILE:dispatch_test> ${caladan_test_config_path}"
)

# dispatch_default_glibc_test (default glibc and junction)
add_executable(dispatch_default_glibc_test
  syscall_testenv.cpp
  dispatch_test.cpp
)
target_link_libraries(dispatch_default_glibc_test
  junction
  gtest_shim
)
target_compile_definitions(dispatch_default_glibc_test PUBLIC
  JUNCTION
)
add_test(
  NAME dispatch_default_glibc_test
  COMMAND sh -c "$<TARGET_FILE:dispatch_default_glibc_test> ${caladan_test_config_path}"
)

# dispatch_native_test (default glibc and NO junction)
add_executable(dispatch_native_test
  syscall_testenv.cpp
  dispatch_test.cpp
)
target_link_libraries(dispatch_native_test
  gtest_main
)
add_test(
  NAME dispatch_native_test
  COMMAND sh -c "$<TARGET_FILE:dispatch_native_test>"
)
