
# Outputs shimjmp_tbl.cpp to build/junction/shim/shimjmp_tbl.cpp
add_custom_command(
    OUTPUT  shimjmp_tbl.cpp intercept.cc
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/shimjmp_tbl.py
      ${CMAKE_CURRENT_SOURCE_DIR}/functions.txt
      ${CMAKE_CURRENT_BINARY_DIR}/shimjmp_tbl.cpp
      ${CMAKE_CURRENT_BINARY_DIR}/intercept.cc
    DEPENDS shimjmp_tbl.py functions.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -Wa,--noexecstack")

# Preload library for glibc.
add_library(shim_preload SHARED
  preload/thread.cc
  intercept.cc
)

add_library(glibc_shim_backend
  backend/init.cc
  backend/sem.cc
  backend/sync.cc
  backend/thread.cc
  shimjmp_tbl.cpp
)

add_executable(tbench_test
  tbench_test.cc
)
target_link_libraries(tbench_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

# add_test(
#   NAME tbench_test_native
#   COMMAND sh -c "$<TARGET_FILE:tbench_test>"
# )

add_test(
  NAME tbench_test_junction
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -- $<TARGET_FILE:tbench_test>"
)
