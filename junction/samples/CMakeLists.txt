message(STATUS "Building junction samples")

# hello_world_native (default glibc and junction)
add_executable(hello_world_native
  hello_world.cpp
)
target_link_libraries(hello_world_native
  junction
)

# hello_world (custom glibc and junction)
add_executable(hello_world
  hello_world.cpp
)
target_link_options(hello_world PUBLIC
  ${JUNCTION_GLIBC}
)
target_link_libraries(hello_world
  junction
)

# Generate inputs for the program
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test.txt "foo")
