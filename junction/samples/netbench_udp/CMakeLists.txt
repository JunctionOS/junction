message(STATUS "Building junction sample: netbench_udp")

# Generate test configurations
set(caladan_config_common
"host_netmask 255.255.255.0
host_gateway 192.168.127.1
runtime_kthreads 10
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 1
runtime_priority lc
runtime_quantum_us 0
enable_directpath 1
host_mtu 9000"
)
set(caladan_server_config
"host_addr 192.168.127.7
${caladan_config_common}"
)
set(caladan_client_config
"host_addr 192.168.127.5
${caladan_config_common}"
)

set(caladan_server_config_path
  ${CMAKE_CURRENT_BINARY_DIR}/caladan_server.config
)
file(WRITE ${caladan_server_config_path} ${caladan_server_config})

set(caladan_client_config_path
  ${CMAKE_CURRENT_BINARY_DIR}/caladan_client.config
)
file(WRITE ${caladan_client_config_path} ${caladan_client_config})

add_executable(netbench_udp
  timing.cc
  fake_worker.cc
  netbench_udp.cc
)
