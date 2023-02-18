message(STATUS "Building junction syscall")


# Outputs syscall_tbl.cc to build/junction/syscall/syscall_tbl.cpp
add_custom_command(
    OUTPUT  syscall_tbl.cc
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/systbl.py
      ${CMAKE_CURRENT_SOURCE_DIR}/syscall_defs.txt
      ${CMAKE_CURRENT_SOURCE_DIR}/usys.txt
      ${CMAKE_CURRENT_BINARY_DIR}/syscall_tbl.cc
    DEPENDS systbl.py syscall_defs.txt systbl.h usys.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_library(syscall
  syscall.cc
  seccomp.cc
  syscall_tbl.cc
  entry.S
)

target_link_libraries(syscall
  kernel
  bindings
)
