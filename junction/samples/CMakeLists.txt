message(STATUS "Building junction samples")

# hello_world
add_executable(hello_world
  hello_world.cc
)

# Generate inputs for the program
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test.txt "foo")
