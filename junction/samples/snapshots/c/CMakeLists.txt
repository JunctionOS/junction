message(STATUS "Building junction snapshot C samples")

# snapshot entrypoint
add_executable(entrypoint
  entrypoint.cc
)

# snapshot multiple calls
add_executable(repeated_snapshot
  repeated_snapshot.cc
)

add_test(
  NAME c_hello_world_snapshot_test
  COMMAND sh -c "rm -f ${metadata} ${elf} && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --\
  $<TARGET_FILE:entrypoint> ${metadata} ${elf}"
)

add_test(
  NAME c_hello_world_restore_test
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  ${metadata} ${elf}"
)
