execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/hello.go ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/snapshot_sys.h ${CMAKE_CURRENT_BINARY_DIR})

add_library(go_snapshot snapshot.c)

set(go_hello "${CMAKE_CURRENT_BINARY_DIR}/hello")

add_custom_command(
  OUTPUT hello
  COMMAND go build -o ${go_hello} ${CMAKE_CURRENT_BINARY_DIR}/hello.go
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hello.go ${CMAKE_CURRENT_BINARY_DIR}/libgo_snapshot.a
)

add_custom_target(go_sample ALL
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/hello)

add_dependencies(go_sample go_snapshot)

# add_test(
#   NAME go_hello_world_snapshot_test
#   COMMAND sh -c "rm -f ${metadata} ${elf} && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --\
# 	  ${go_hello} snap ${elf} ${metadata}"
# )

# set_tests_properties(go_hello_world_snapshot_test PROPERTIES
#   PASS_REGULAR_EXPRESSION "Snapshotted"
#   FAIL_REGULAR_EXPRESSION "FAILED;Restored!;Abort"
# )

# add_test(
# NAME go_hello_world_restore_test
#  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
# 	 ${metadata} ${elf}"
# )

# set_tests_properties(go_hello_world_restore_test PROPERTIES
#  PASS_REGULAR_EXPRESSION "Restored!"
# )
