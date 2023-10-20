message(STATUS "Building junction base")

add_library(base
  arch.cc
  error.cc
  io.cc
  time.cc
)

add_executable(slab_list_test
  slab_list_test.cc
)
target_link_libraries(slab_list_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

add_test(
  NAME slab_list_test
  COMMAND sh -c "$<TARGET_FILE:slab_list_test>"
)
