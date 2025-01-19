message(STATUS "Building junction samples")

add_subdirectory(filesystem)
add_subdirectory(netbench_udp)
add_subdirectory(netperf_tcp)
add_subdirectory(tcp)
add_subdirectory(udp)

if(SNAPSHOT_SAMPLES)
  add_subdirectory(cereal)
  add_subdirectory(snapshots)
endif()

add_subdirectory(nbody)

add_executable(unix_socket_test
  unix_socket_test.cc
)

add_test(
  NAME unix_socket_test_native
  COMMAND sh -c "$<TARGET_FILE:unix_socket_test>"
)

add_test(
  NAME unix_socket_test_junction
  COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${caladan_test_config_path} $EXTRA_JUNCTION_FLAGS -- $<TARGET_FILE:unix_socket_test>"
)