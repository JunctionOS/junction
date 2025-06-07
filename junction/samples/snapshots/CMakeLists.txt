message(STATUS "Building junction sample: snapshot")

macro(add_snapshot_restore_test_stop_count test_name stop_count test_commands)

  set(CONFIG ${caladan_test_config_path_ts_st})
  set(PREFIX /tmp/${test_name})

  set(ELF_METADATA ${PREFIX}.metadata)
  set(ELF ${PREFIX}.elf)

  set(JIF_METADATA ${PREFIX}.jm)
  set(JIF ${PREFIX}.jif)
  set(JIF_ITREES_ORD ${PREFIX}_itrees_ord.jif)
  set(JIF_FRAGMENTED_ORD ${PREFIX}_fragmented_ord.jif)

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
    NAME ${test_name}_process_jifs
    COMMAND sh -c "${JIFTOOL} $CHROOT_DIR/${JIF} \"build-itrees $CHROOT_DIR\" \"add-ord $CHROOT_DIR/${ORD}\" \"write $CHROOT_DIR/${JIF_ITREES_ORD}\" && ${READJIF} --check $CHROOT_DIR/${JIF_ITREES_ORD} && ${JIFTOOL} $CHROOT_DIR/${JIF} \"fragment-vmas $CHROOT_DIR\" \"add-ord $CHROOT_DIR/${ORD}\" \"write $CHROOT_DIR/${JIF_FRAGMENTED_ORD}\" && ${READJIF} --check $CHROOT_DIR/${JIF_FRAGMENTED_ORD}"
  )

  add_test(
    NAME ${test_name}_restore_jif
    COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS --jif --stackswitch --mem-trace --mem-trace-out ${ORD} -r -- ${JIF_METADATA} ${JIF}"
  )

  add_test(
    NAME ${test_name}_restore_itrees_ord_jif
    COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS --jif -r -- ${JIF_METADATA} ${JIF_ITREES_ORD}"
  )

  add_test(
    NAME ${test_name}_restore_fragmented_ord_jif
    COMMAND sh -c "sudo -E $<TARGET_FILE:junction_run> ${CONFIG} $EXTRA_JUNCTION_FLAGS --jif -r -- ${JIF_METADATA} ${JIF_FRAGMENTED_ORD}"
  )

  add_test(
    NAME ${test_name}_post_actions
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/clean_test_outputs.sh
            ${JIF_METADATA}
            ${JIF}
            ${JIF_ITREES_ORD}
            ${JIF_FRAGMENTED_ORD}
            ${ELF_METADATA}
            ${ELF}
            ${ORD}
  )

  set_tests_properties(${test_name}_post_actions PROPERTIES FIXTURES_CLEANUP cleanup_${test_name})

  foreach(dep_test IN ITEMS
    ${test_name}_snapshot_elf
    ${test_name}_restore_elf
    ${test_name}_snapshot_jif
    ${test_name}_process_jifs
    ${test_name}_restore_jif
    ${test_name}_restore_itrees_ord_jif
    ${test_name}_restore_fragmented_ord_jif
  )
    set_tests_properties(${dep_test} PROPERTIES FIXTURES_REQUIRED cleanup_${test_name})
  endforeach()

  set_tests_properties(${test_name}_restore_elf PROPERTIES DEPENDS ${test_name}_snapshot_elf)
  set_tests_properties(${test_name}_restore_jif PROPERTIES DEPENDS ${test_name}_snapshot_jif)
  set_tests_properties(${test_name}_process_jifs PROPERTIES DEPENDS ${test_name}_restore_jif)
  set_tests_properties(${test_name}_restore_itrees_ord_jif PROPERTIES DEPENDS ${test_name}_process_jifs)
  set_tests_properties(${test_name}_restore_fragmented_ord_jif PROPERTIES DEPENDS ${test_name}_process_jifs)
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
