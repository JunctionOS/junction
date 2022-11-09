message(STATUS "Building junction syscall")

add_library(syscall
  dispatch.cpp
  seccomp_filtering.cpp
)

target_link_libraries(syscall
  kernel
  bindings
)
