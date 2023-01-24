message(STATUS "Building junction sample: netperf_tcp")

# Generate test configurations
set(caladan_server_config
"host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads 1
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 1
runtime_priority lc
runtime_quantum_us 0
enable_directpath 1
host_mtu 9000
host_addr 192.168.127.7"
)

set(caladan_server_config_path
  ${CMAKE_CURRENT_BINARY_DIR}/caladan_server.config
)
file(WRITE ${caladan_server_config_path} ${caladan_server_config})

# netperf_tcp_server
add_executable(netperf_tcp_server
  server.cc
)
