# Generate test configurations
set(caladan_config_common
"host_netmask 255.255.255.0
host_gateway 10.10.1.3
runtime_kthreads 4
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 4
runtime_priority lc
runtime_quantum_us 0"
)

# gateway
set(caladan_gateway_config
"host_addr 10.10.1.1
${caladan_config_common}"
)

set(caladan_gateway_config_path
    ${CMAKE_CURRENT_BINARY_DIR}/caladan_gateway.config
)
file(WRITE ${caladan_gateway_config_path} ${caladan_gateway_config})

add_executable(gateway 
    gateway.cc
    lib/httplib.h
)

# controller
set(caladan_controller_config
"host_addr 10.10.1.2
${caladan_config_common}"
)

set(caladan_controller_config_path
    ${CMAKE_CURRENT_BINARY_DIR}/caladan_controller.config
)
file(WRITE ${caladan_controller_config_path} ${caladan_controller_config})

add_executable(controller 
    controller.cc
    lib/httplib.h
)

# services
add_executable(user_service
    user_service.cc
    lib/httplib.h
    watchdog.cc
    gateway_client.cc
)

add_executable(follower_service
    follower_service.cc
    lib/httplib.h
    watchdog.cc
    gateway_client.cc
)

add_executable(proxy_service
    proxy_service.cc
    lib/httplib.h
)
