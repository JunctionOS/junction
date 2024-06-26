set(node_hello "${CMAKE_CURRENT_SOURCE_DIR}/hello.js")

# node_hello
add_test(
 NAME node_hello_snapshot
 COMMAND sh -c "rm -f /tmp/node_hello.metadata /tmp/node_hello.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/node_hello --\
 /usr/bin/node ${node_hello}"
)

add_test(
 NAME node_hello_restore
 COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
 /tmp/node_hello.metadata /tmp/node_hello.elf"
)
