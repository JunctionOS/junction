# copy source files

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/hello.py ${CMAKE_CURRENT_BINARY_DIR}/hello.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/python_resizer.py ${CMAKE_CURRENT_BINARY_DIR}/python_resizer.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/numpy_test.py ${CMAKE_CURRENT_BINARY_DIR}/numpy_test.py COPYONLY)


set(python_hello_world "${CMAKE_CURRENT_BINARY_DIR}/hello.py")
set(python_resizer "${CMAKE_CURRENT_BINARY_DIR}/python_resizer.py")
set(python_numpy "${CMAKE_CURRENT_BINARY_DIR}/numpy_test.py")

set(venv_python
  "${CMAKE_SOURCE_DIR}/bin/venv/bin/python3"
)

file(
 GLOB images "${image_dir}/*"
)
foreach(
 image ${images}
)
get_filename_component(image_name ${image} NAME)

add_snapshot_restore_test(python_resizer_${image_name} "${venv_python} ${python_resizer} ${image_dir}/${image_name} ${thumb_dir}/${image_name}")
endforeach()

add_snapshot_restore_test(python_hello_world "${venv_python} ${python_hello_world}")
add_snapshot_restore_test(python_numpy "${venv_python} ${python_numpy}")

add_subdirectory(function_bench)
