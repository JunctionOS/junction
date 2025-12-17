message(STATUS "Building junction sample: serverless")

# Generate test configurations
set(caladan_config_common
"host_netmask 255.255.255.0
runtime_kthreads 4
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 4
runtime_priority lc
runtime_quantum_us 0"
)

set(caladan_function_config
"host_addr 10.10.1.3
host_gateway 10.10.1.2
${caladan_config_common}"
)

set(caladan_client_config
"host_addr 10.10.1.2
host_gateway 10.10.1.1
${caladan_config_common}"
)

set(caladan_gateway_config
"host_addr 10.10.1.1
host_gateway 10.10.1.2
${caladan_config_common}"
)

set(caladan_function_config_path
    ${CMAKE_CURRENT_BINARY_DIR}/caladan_function.config
)
file(WRITE ${caladan_function_config_path} ${caladan_function_config})

set(caladan_client_config_path
    ${CMAKE_CURRENT_BINARY_DIR}/caladan_client.config
)
file(WRITE ${caladan_client_config_path} ${caladan_client_config})

set(caladan_gateway_config_path
    ${CMAKE_CURRENT_BINARY_DIR}/caladan_gateway.config
)
file(WRITE ${caladan_gateway_config_path} ${caladan_gateway_config})

# function
add_executable(function 
    function.cc
)

# client
add_executable(client client.cc)

# gateway
add_executable(gateway gateway.cc)
