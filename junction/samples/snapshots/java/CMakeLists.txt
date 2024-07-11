
find_package(Java)

add_snapshot_restore_test_stop_count(java_resizer 2 "${Java_JAVA_EXECUTABLE} -cp ${CMAKE_CURRENT_SOURCE_DIR}/jna-5.14.0.jar ${CMAKE_CURRENT_SOURCE_DIR}/Resizer.java ${CMAKE_CURRENT_SOURCE_DIR}/../images/IMG_4011.jpg")
