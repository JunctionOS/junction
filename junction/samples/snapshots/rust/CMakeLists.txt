message(STATUS "Building junction snapshot rust samples")
# Add corrosion: a way to build rust code in Cmake
include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.4 # Optionally specify a commit hash, version tag or branch here
)
# Set any global configuration variables such as `Rust_TOOLCHAIN` before this line!
FetchContent_MakeAvailable(Corrosion)

# add images
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}
)


# add rust crate
corrosion_import_crate(MANIFEST_PATH resize-rs/Cargo.toml)
