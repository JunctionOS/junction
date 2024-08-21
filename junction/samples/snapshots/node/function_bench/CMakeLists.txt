message(STATUS "setting up node function bench tests")

foreach(f IN ITEMS ${CMAKE_CURRENT_SOURCE_DIR}/)
    file(COPY ${f} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()
