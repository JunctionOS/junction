# copy source files

find_package(Python3 COMPONENTS Interpreter)

execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}
)
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/hello.py ${CMAKE_CURRENT_BINARY_DIR}
)
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/numpy_test.py ${CMAKE_CURRENT_BINARY_DIR}
)
execute_process(
  COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/python_resizer.py ${CMAKE_CURRENT_BINARY_DIR}
)

set(python_hello "${CMAKE_CURRENT_BINARY_DIR}/hello.py")
set(python_resizer "${CMAKE_CURRENT_BINARY_DIR}/python_resizer.py")
set(python_numpy "${CMAKE_CURRENT_BINARY_DIR}/numpy_test.py")
set(images_path "${CMAKE_CURRENT_BINARY_DIR}/images")
set(thumbnails "${CMAKE_CURRENT_BINARY_DIR}/thumbnails")

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

#add_test(
#  NAME python_hello_world_snapshot_test
#  COMMAND sh -c "rm -f ${metadata} ${elf} && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --\
#  ${Python3_EXECUTABLE} ${python_hello} snap ${metadata} ${elf}"
#)
#
#add_test(
#  NAME python_hello_world_restore_test
#  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r -- ${metadata} ${elf}"
#)
#
#add_test(
#  NAME python_resizer_snapshot_test
#  COMMAND sh -c "rm -f ${metadata} ${elf} && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --\
#  ${Python3_EXECUTABLE} ${python_resizer} ${images_path}/almost_dayrise_house.jpg\
#  -s --elf ${elf} --metadata ${metadata} -c ${thumbnails}/almost_dayrise_house.jpg"
#)
#
#add_test(
#  NAME python_resizer_restore_test
#  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r -- \
#  ${metadata} ${elf}"
#)

# add_test(
#   NAME python_numpy_snapshot_test
#   COMMAND sh -c "rm -f ${metadata} ${elf} && $<TARGET_FILE:junction_run> ${caladan_test_config_path} --\
#   $(which python) ${python_numpy} snap ${metadata} ${elf}"
# )

# add_test(
#   NAME python_numpy_restore_test
#   COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
#   ${metadata} ${elf}"
# )


