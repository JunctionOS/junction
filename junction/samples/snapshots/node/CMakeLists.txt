
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/hello.js ${CMAKE_CURRENT_BINARY_DIR}/hello.js COPYONLY)

set(node_hello "${CMAKE_CURRENT_BINARY_DIR}/hello.js")

add_snapshot_restore_test(node_hello "/usr/bin/node ${node_hello}")

add_subdirectory(function_bench)
