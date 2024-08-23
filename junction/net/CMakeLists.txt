message(STATUS "Building junction net")

# Library
add_library(net
  net.cc
  caladan_poll.cc
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
