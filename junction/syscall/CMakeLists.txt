message(STATUS "Building junction syscall")

set(SOURCES_C_CPP
  handlers.cpp
  intercept.cpp
  seccomp_filtering.cpp
)

set(SOURCES_ASM
  no_intercept.S
)

add_library(syscall_c_cpp OBJECT ${SOURCES_C_CPP})
add_library(syscall_asm OBJECT ${SOURCES_ASM})

add_library(syscall STATIC
  $<TARGET_OBJECTS:syscall_c_cpp>
  $<TARGET_OBJECTS:syscall_asm>
)

target_link_libraries(syscall
  bindings
  filesystem
  memorysystem
)
