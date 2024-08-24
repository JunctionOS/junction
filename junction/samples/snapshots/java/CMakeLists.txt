find_package(Java)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/jna-5.14.0.jar ${CMAKE_CURRENT_BINARY_DIR}/jna-5.14.0.jar COPYONLY)
add_subdirectory(resizer)
