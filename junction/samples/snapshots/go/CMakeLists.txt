execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/go.mod ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/go.sum ${CMAKE_CURRENT_BINARY_DIR})

# copy images
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}
)

set(go_hello "${CMAKE_CURRENT_BINARY_DIR}/hello")
set(go_resizer "${CMAKE_CURRENT_BINARY_DIR}/resizer")

add_custom_command(
  OUTPUT hello
  COMMAND go build -o ${go_hello} ${CMAKE_CURRENT_SOURCE_DIR}/hello.go
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hello.go
)

add_custom_command(
  OUTPUT resizer
  COMMAND go build -o ${go_resizer} ${CMAKE_CURRENT_SOURCE_DIR}/resizer.go
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hello.go
)

add_custom_target(go_hello_world ALL
  DEPENDS ${go_hello})

add_custom_target(go_resizer_bin ALL
  DEPENDS ${go_resizer}
)

# go_hello_world
add_snapshot_restore_test(go_hello_world "${go_hello}")