# copy source files

find_package(Python3 COMPONENTS Interpreter)

set(python_hello_world "${CMAKE_CURRENT_SOURCE_DIR}/hello.py")
set(python_resizer "${CMAKE_CURRENT_SOURCE_DIR}/python_resizer.py")
set(python_numpy "${CMAKE_CURRENT_SOURCE_DIR}/numpy_test.py")
set(images_path "${CMAKE_CURRENT_SOURCE_DIR}/images")
set(thumbnails "${CMAKE_CURRENT_SOURCE_DIR}/thumbnails")

# generate all the thumbnails
#file(
#  MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/thumbnails
#)
#file(
#  GLOB images "${images_path}/*"
#)
#foreach(
#  image ${images}
#)
#execute_process(
#  COMMAND python ${CMAKE_CURRENT_BINARY_DIR}/python_resizer.py ${image}
#)
#endforeach()

# python_hello_world
add_test(
  NAME python_hello_world_snapshot
  COMMAND sh -c "rm -f /tmp/python_hello_world.metadata /tmp/python_hello_world.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --ld_preload -S 1 --snapshot-prefix /tmp/python_hello_world --\
  ${Python3_EXECUTABLE} ${python_hello_world}"
)

add_test(
  NAME python_hello_world_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} --ld_preload -r --\
  /tmp/python_hello_world.metadata /tmp/python_hello_world.elf"
)

# python_numpy
add_test(
  NAME python_numpy_snapshot
  COMMAND sh -c "rm -f /tmp/python_numpy.metadata /tmp/python_numpy.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --ld_preload -S 1 --snapshot-prefix /tmp/python_numpy --\
  ${Python3_EXECUTABLE} ${python_numpy}"
)

add_test(
  NAME python_numpy_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} --ld_preload -r --\
  /tmp/python_numpy.metadata /tmp/python_numpy.elf"
)
