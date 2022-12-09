message(STATUS "Building junction net")

# Library
add_library(net
  socket_placeholder.cc
  tcp_listener_socket.cc
  net.cc
)

target_link_libraries(net
  base
  bindings
  kernel
)

add_executable(tcp_bench_test
  tcp_bench_test.cc
)
target_link_libraries(tcp_bench_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

add_test(
  NAME tcp_bench_test_native
  COMMAND sh -c "$<TARGET_FILE:tcp_bench_test>"
)

add_test(
  NAME tcp_bench_test_junction
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -- $<TARGET_FILE:tcp_bench_test>"
)
