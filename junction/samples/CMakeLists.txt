message(STATUS "Building junction samples")

add_subdirectory(filesystem)
add_subdirectory(hello_world)
add_subdirectory(netbench_udp)
add_subdirectory(netperf_tcp)
add_subdirectory(tcp)
add_subdirectory(udp)

if(SNAPSHOT_SAMPLES)
  add_subdirectory(snapshots)
endif()
