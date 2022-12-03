message(STATUS "Building junction base")

add_library(base
	arch.cc
	error.cc
	io.cc
)
