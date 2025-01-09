# Outputs shimjmp_tbl.cpp to build/junction/shim/shimjmp_tbl.cpp

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_command(
    OUTPUT  shimjmp_tbl.cpp intercept.cc
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/shimjmp_tbl.py
      ${CMAKE_CURRENT_SOURCE_DIR}/functions.txt
      ${CMAKE_CURRENT_BINARY_DIR}/shimjmp_tbl.cpp
      ${CMAKE_CURRENT_BINARY_DIR}/intercept.cc
    DEPENDS shimjmp_tbl.py functions.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -Wa,--noexecstack")

# Preload library for glibc.
add_library(shim_preload SHARED
  intercept.cc
  frontend.cc
)

add_library(glibc_shim_backend
  backend/init.cc
  backend/sem.cc
  backend/sync.cc
  shimjmp_tbl.cpp
)

add_executable(child_test
  child_test.cc
)

add_compile_definitions(POSIX_SPAWN_CHILD_BIN=\"$<TARGET_FILE:child_test>\")

add_executable(tbench_test
  tbench_test.cc
)
target_link_libraries(tbench_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

set(MEASURE_ROUNDS "10000") # set higher for real benchmarking

add_test(
  NAME tbench_test_native
  COMMAND sh -c "MEASURE_ROUNDS=${MEASURE_ROUNDS} $<TARGET_FILE:tbench_test>"
)

add_test(
  NAME tbench_test_junction_all_optimization
  COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS -E MEASURE_ROUNDS=${MEASURE_ROUNDS} --ld_preload=$<TARGET_FILE:shim_preload> -- $<TARGET_FILE:tbench_test>"
)

add_test(
  NAME tbench_test_junction_no_optimization
  COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS --glibc_path --interpreter_path --ld_preload -E MEASURE_ROUNDS=${MEASURE_ROUNDS} -- $<TARGET_FILE:tbench_test>"
)

add_test(
  NAME tbench_test_junction_plus_custom_libc
  COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS --ld_preload -E MEASURE_ROUNDS=${MEASURE_ROUNDS} -- $<TARGET_FILE:tbench_test>"
)

add_test(
  NAME tbench_test_junction_plus_shim
  COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS --glibc_path --interpreter_path --ld_preload=$<TARGET_FILE:shim_preload> -E MEASURE_ROUNDS=${MEASURE_ROUNDS} -- $<TARGET_FILE:tbench_test>"
)

add_test(
  NAME tbench_test_stackswitch
  COMMAND sh -c "sudo -E  $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS --stackswitch -E MEASURE_ROUNDS=${MEASURE_ROUNDS} -- $<TARGET_FILE:tbench_test>"
)
