message(STATUS "Building junction sample: snapshot")

macro(add_snapshot_restore_test_stop_count test_name stop_count test_commands)

  set(CONFIG ${caladan_test_config_path_ts_st})
  set(PREFIX /tmp/${test_name})

  set(ELF_METADATA ${PREFIX}.metadata)
  set(ELF ${PREFIX}.elf)

  set(JIF_METADATA ${PREFIX}.jm)
  set(JIF ${PREFIX}.jif)
  set(JIF_ITREES ${PREFIX}_itrees.jif)
  set(JIF_ITREES_ORD ${PREFIX}_itrees_ord.jif)

  set(ORD ${PREFIX}.ord)

  add_test(
    NAME ${test_name}_snapshot_elf
    COMMAND sh -c "rm -f $CHROOT_DIR/${ELF_METADATA} $CHROOT_DIR/${ELF} && sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS -S ${stop_count} --snapshot-prefix ${PREFIX} -- ${test_commands}"
  )

  add_test(
    NAME ${test_name}_restore_elf
    COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS -r -- ${ELF_METADATA} ${ELF}"
  )

  add_test(
    NAME ${test_name}_snapshot_jif
    COMMAND sh -c "rm -f $CHROOT_DIR/${JIF_METADATA} $CHROOT_DIR/${JIF} && sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS --jif -S ${stop_count} --snapshot-prefix ${PREFIX} -- ${test_commands} && ${READJIF} --check $CHROOT_DIR/${JIF}"
  )

  add_test(
    NAME ${test_name}_build_itrees
    COMMAND sh -c "${JIFTOOL} $CHROOT_DIR/${JIF} $CHROOT_DIR/${JIF_ITREES} build-itrees && ${READJIF} --check $CHROOT_DIR/${JIF_ITREES}"
  )

  add_test(
    NAME ${test_name}_restore_jif
    COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS --jif --stackswitch --mem-trace --mem-trace-out ${ORD} -r -- ${JIF_METADATA} ${JIF}"
  )

  add_test(
    NAME ${test_name}_add_ord
    COMMAND sh -c "${JIFTOOL} $CHROOT_DIR/${JIF_ITREES} $CHROOT_DIR/${JIF_ITREES_ORD} add-ord $CHROOT_DIR/${ORD} && ${READJIF} --check $CHROOT_DIR/${JIF_ITREES_ORD}"
  )

  add_test(
    NAME ${test_name}_restore_itrees_ord_jif
    COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS --jif -r -- ${JIF_METADATA} ${JIF_ITREES_ORD}"
  )

  set_tests_properties(${test_name}_restore_elf PROPERTIES DEPENDS ${test_name}_snapshot_elf)
  set_tests_properties(${test_name}_build_itrees PROPERTIES DEPENDS ${test_name}_snapshot_jif)
  set_tests_properties(${test_name}_restore_jif PROPERTIES DEPENDS ${test_name}_snapshot_jif)
  set_tests_properties(${test_name}_add_ord PROPERTIES DEPENDS ${test_name}_restore_jif)
  set_tests_properties(${test_name}_restore_itrees_ord_jif PROPERTIES DEPENDS ${test_name}_build_itrees)
  set_tests_properties(${test_name}_restore_itrees_ord_jif PROPERTIES DEPENDS ${test_name}_add_ord)
endmacro()

macro(add_snapshot_restore_test test_name test_commands)
  add_snapshot_restore_test_stop_count(${test_name} 1 ${test_commands})
endmacro()

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/images" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/thumbnails" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

set(image_dir "${CMAKE_CURRENT_BINARY_DIR}/images")
set(thumb_dir "${CMAKE_CURRENT_BINARY_DIR}/thumbnails")

add_subdirectory(c)
add_subdirectory(go)
add_subdirectory(java)
add_subdirectory(node)
add_subdirectory(python)
add_subdirectory(rust)
