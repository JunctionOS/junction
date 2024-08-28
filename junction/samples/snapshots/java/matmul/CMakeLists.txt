configure_file(${CMAKE_CURRENT_SOURCE_DIR}/MatMul.java ${CMAKE_CURRENT_BINARY_DIR}/MatMul.java COPYONLY)

add_snapshot_restore_test_stop_count(java_matmul 2 "${Java_JAVA_EXECUTABLE} -cp ${CMAKE_CURRENT_BINARY_DIR}/../jar/jna-5.14.0.jar:${CMAKE_CURRENT_BINARY_DIR}/../jar/json-simple-1.1.1.jar ${CMAKE_CURRENT_BINARY_DIR}/MatMul.java")
