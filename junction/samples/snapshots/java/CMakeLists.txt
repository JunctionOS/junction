find_package(Java)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/jar/jna-5.14.0.jar ${CMAKE_CURRENT_BINARY_DIR}/jar/jna-5.14.0.jar COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/jar/json-simple-1.1.1.jar ${CMAKE_CURRENT_BINARY_DIR}/jar/json-simple-1.1.1.jar COPYONLY)
add_subdirectory(resizer)
add_subdirectory(matmul)
