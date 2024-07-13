message(STATUS "Building junction sample: snapshot")

macro(add_snapshot_restore_test_stop_count test_name stop_count test_commands)

  # Uncomment below to have snapshot tests run with a single kthread.
  # add_test(
  #   NAME ${test_name}_snapshot_st
  #   COMMAND sh -c "rm -f /tmp/${test_name}.metadata /tmp/${test_name}.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path_ts_st} -S ${stop_count} --snapshot-prefix /tmp/${test_name} -- ${test_commands}"
  # )

  # add_test(
  #   NAME ${test_name}_restore_st
  #   COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path_ts_st} -r -- /tmp/${test_name}.metadata /tmp/${test_name}.elf"
  # )

  # set_tests_properties(${test_name}_restore_st PROPERTIES DEPENDS ${test_name}_snapshot_st)

  add_test(
    NAME ${test_name}_snapshot_elf
    COMMAND sh -c "rm -f /tmp/${test_name}.metadata /tmp/${test_name}.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S ${stop_count} --snapshot-prefix /tmp/${test_name} -- ${test_commands}"
  )

  add_test(
    NAME ${test_name}_restore_elf
    COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r -- /tmp/${test_name}.metadata /tmp/${test_name}.elf && rm -f /tmp/${test_name}.metadata /tmp/${test_name}.elf"
  )

  add_test(
    NAME ${test_name}_snapshot_jif
    COMMAND sh -c "rm -f /tmp/${test_name}.jm /tmp/${test_name}.jif && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --jif -S ${stop_count} --snapshot-prefix /tmp/${test_name} -- ${test_commands} && ${READJIF} --check /tmp/${test_name}.jif"
  )

  add_test(
    NAME ${test_name}_build_itrees
    COMMAND sh -c "${JIFTOOL} /tmp/${test_name}.jif /tmp/${test_name}_itrees.jif build-itrees && ${READJIF} --check /tmp/${test_name}_itrees.jif && cp /tmp/${test_name}.jm /tmp/${test_name}_itrees.jm"
  )

  add_test(
    NAME ${test_name}_restore_jif
    COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} --jif -r -- /tmp/${test_name}.jm /tmp/${test_name}.jif && rm -f /tmp/${test_name}.jm /tmp/${test_name}.jif"
  )

  add_test(
    NAME ${test_name}_restore_jif_itrees
    COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} --jif -r -- /tmp/${test_name}_itrees.jm /tmp/${test_name}_itrees.jif && rm -f /tmp/${test_name}_itrees.jm /tmp/${test_name}_itrees.jif"
  )

  set_tests_properties(${test_name}_restore_elf PROPERTIES DEPENDS ${test_name}_snapshot_elf)
  set_tests_properties(${test_name}_build_itrees PROPERTIES DEPENDS ${test_name}_snapshot_jif)
  set_tests_properties(${test_name}_restore_jif PROPERTIES DEPENDS ${test_name}_snapshot_jif)
  set_tests_properties(${test_name}_restore_jif_itrees PROPERTIES DEPENDS ${test_name}_build_itrees)

endmacro()

macro(add_snapshot_restore_test test_name test_commands)
  add_snapshot_restore_test_stop_count(${test_name} 1 ${test_commands})
endmacro()

add_subdirectory(c)
add_subdirectory(go)
add_subdirectory(java)
add_subdirectory(node)
add_subdirectory(python)
add_subdirectory(rust)
