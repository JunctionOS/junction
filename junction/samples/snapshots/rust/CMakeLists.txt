message(STATUS "Building junction snapshot rust samples")

# add images
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}
)

# add rust crate
corrosion_import_crate(MANIFEST_PATH resize-rs/Cargo.toml)

set(rust_resizer "${CMAKE_CURRENT_BINARY_DIR}/resize-rs")

add_snapshot_restore_test(rust_resizer "${rust_resizer} ${image_dir}/IMG_4011.jpg")
add_snapshot_restore_test(rust_resizer_small "${rust_resizer} ${thumb_dir}/IMG_4011.jpg")