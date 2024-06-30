message(STATUS "Building junction snapshot rust samples")

# add images
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}
)

# add rust crate
corrosion_import_crate(MANIFEST_PATH resize-rs/Cargo.toml)

set(rust_resizer "${CMAKE_CURRENT_BINARY_DIR}/resize-rs")

# rust resizer
add_test(
  NAME rust_resizer_snapshot
  COMMAND sh -c "rm -f /tmp/rust_resizer.metadata /tmp/rust_resizer.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/rust_resizer --\
  ${rust_resizer} ${CMAKE_CURRENT_SOURCE_DIR}/../images/IMG_4011.jpg"
)

add_test(
  NAME rust_resizer_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/rust_resizer.metadata /tmp/rust_resizer.elf"
)
