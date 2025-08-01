message(STATUS "Building junction net")

# Library
add_library(net
  net.cc
  netlink.cc
  caladan_poll.cc
  unix_socket.cc
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

test_bin(tcp_bench_test "$<TARGET_FILE:tcp_bench_test>")

add_executable(udp_bench_test
  udp_bench_test.cc
)
target_link_libraries(udp_bench_test
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,gtest_main>"
)

test_bin(udp_bench_test "$<TARGET_FILE:udp_bench_test>")

add_executable(unix_socket_stream_test
  unix_socket_test.cc
)

add_executable(unix_socket_dgram_test
  unix_socket_test_dgram.cc
)

test_bin(unix_socket_stream_test "$<TARGET_FILE:unix_socket_stream_test>")
test_bin(unix_socket_dgram_test "$<TARGET_FILE:unix_socket_dgram_test>")
