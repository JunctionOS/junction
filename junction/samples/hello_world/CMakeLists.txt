message(STATUS "Building junction sample: hello_world")

# hello_world
add_executable(hello_world
  hello_world.cc
)
# Generate inputs for the hello_world program
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/testdata/test.txt "foo")

