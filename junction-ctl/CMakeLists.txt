message(STATUS "Building junction-ctl")

corrosion_import_crate(MANIFEST_PATH Cargo.toml)
add_dependencies(cargo-prebuild_junction-ctl control_schema_rs)
