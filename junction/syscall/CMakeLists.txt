message(STATUS "Building junction syscall")

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Outputs syscall_tbl.cc to build/junction/syscall/syscall_tbl.cpp
add_custom_command(
    OUTPUT  syscall_tbl.cc
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/systbl.py
      ${CMAKE_CURRENT_SOURCE_DIR}/usys.txt
      ${CMAKE_CURRENT_BINARY_DIR}/syscall_tbl.cc
    DEPENDS systbl.py systbl.h usys.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_library(vdso SHARED vdso/vdso.S)
set_target_properties(vdso PROPERTIES LINKER_LANGUAGE CXX)

target_link_options(vdso PRIVATE
    -shared
    -nostartfiles
    -fPIC
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/vdso/vdso.lds
    -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/vdso/vdso.ld
    -z noexecstack
)

set_target_properties(vdso PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/vdso/vdso.lds)

set_target_properties(vdso PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/vdso/vdso.ld)


add_library(syscall
  syscall.cc
  seccomp.cc
  strace.cc
  syscall_tbl.cc
  entry.S
  vdso/vdso_inc.S
)

set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/vdso/vdso_inc.S
  PROPERTIES OBJECT_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libvdso.so"
)

add_dependencies(syscall vdso)

target_link_libraries(syscall
  kernel
  bindings
)
