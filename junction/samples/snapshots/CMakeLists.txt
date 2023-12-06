message(STATUS "Building junction sample: snapshot")

# Generate inputs and thumbnail dir for the snapshot program
add_custom_target(copy_images
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}/images
)
add_custom_target(mk_thumbnail_dir
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/thumbnails
)

add_custom_target(python_resizer
    SOURCES python_resizer.py
)
add_dependencies(python_resizer copy_images mk_thumbnail_dir)

add_subdirectory(snapshot-basic)
