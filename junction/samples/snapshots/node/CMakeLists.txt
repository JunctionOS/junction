set(node_hello "${CMAKE_CURRENT_SOURCE_DIR}/hello.js")

add_snapshot_restore_test(node_hello "/usr/bin/node ${node_hello}")
