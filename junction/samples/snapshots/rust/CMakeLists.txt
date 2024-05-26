message(STATUS "Building junction snapshot rust samples")

# add images
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}
)

# add rust crate
corrosion_import_crate(MANIFEST_PATH resize-rs/Cargo.toml)
