configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Resizer.java ${CMAKE_CURRENT_BINARY_DIR}/Resizer.java COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../../images/IMG_4011.jpg ${CMAKE_CURRENT_BINARY_DIR}/IMG_4011.jpg COPYONLY)

add_snapshot_restore_test_stop_count(java_resizer 2 "${Java_JAVA_EXECUTABLE} -cp ${CMAKE_CURRENT_BINARY_DIR}/../jna-5.14.0.jar ${CMAKE_CURRENT_BINARY_DIR}/Resizer.java ${CMAKE_CURRENT_BINARY_DIR}/IMG_4011.jpg")
