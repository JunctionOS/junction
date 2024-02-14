message(STATUS "Building junction sample: snapshot")

set(metadata "snapshot.metadata")
set(elf "snapshot.elf")

add_subdirectory(c)
add_subdirectory(go)
add_subdirectory(node)
add_subdirectory(python)
add_subdirectory(rust)
