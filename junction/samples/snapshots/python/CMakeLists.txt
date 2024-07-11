# copy source files

find_package(Python3 COMPONENTS Interpreter)

set(python_hello_world "${CMAKE_CURRENT_SOURCE_DIR}/hello.py")
set(python_resizer "${CMAKE_CURRENT_SOURCE_DIR}/python_resizer.py")
set(python_numpy "${CMAKE_CURRENT_SOURCE_DIR}/numpy_test.py")
set(images_path "${CMAKE_CURRENT_SOURCE_DIR}/images")
set(thumbnails "${CMAKE_CURRENT_SOURCE_DIR}/thumbnails")

file(
 GLOB images "${images_path}/*"
)
foreach(
 image ${images}
)
get_filename_component(image_name ${image} NAME)
add_snapshot_restore_test(python_resizer_${image_name} "${Python3_EXECUTABLE} ${python_resizer} ${images_path}/${image_name} ${thumbnails}/${image_name}")
endforeach()

add_snapshot_restore_test(python_hello_world "${Python3_EXECUTABLE} ${python_hello_world}")
add_snapshot_restore_test(python_numpy "${Python3_EXECUTABLE} ${python_numpy}")

add_subdirectory(function_bench)
