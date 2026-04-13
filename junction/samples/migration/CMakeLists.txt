message(STATUS "Building junction migration samples")

# Generate test configurations
set(caladan_config_common
"host_netmask 255.255.255.0
runtime_kthreads 4
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 4
runtime_priority lc
runtime_quantum_us 0"
)

set(caladan_service_config
"host_addr 10.10.1.1
host_gateway 10.10.1.2
${caladan_config_common}"
)

set(caladan_migration_dst_config
"host_addr 10.10.1.2
host_gateway 10.10.1.1
${caladan_config_common}"
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/caladan_service.config
    ${caladan_service_config})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/caladan_migration_dst.config
    ${caladan_migration_dst_config})

add_executable(counter_service
  counter_service.cc
)
