
find_package(Java)

# go_hello_world
add_test(
  NAME java_resizer_snapshot
  COMMAND sh -c "rm -f /tmp/java_resizer.metadata /tmp/java_resizer.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/java_resizer --\
  ${Java_JAVA_EXECUTABLE} -cp ${CMAKE_CURRENT_SOURCE_DIR}/jna-5.14.0.jar ${CMAKE_CURRENT_SOURCE_DIR}/Resizer.java ${CMAKE_CURRENT_SOURCE_DIR}/../images/IMG_4011.jpg"
)

add_test(
  NAME java_resizer_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/java_resizer.metadata /tmp/java_resizer.elf"
)
