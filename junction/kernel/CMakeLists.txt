message(STATUS "Building junction kernel")

set(SOURCES_C_CPP
  elf.cc
  file.cc
  stdiofile.cc
  pipe.cc
  proc.cc
  exec.cc
  futex.cc
  poll.cc
  random.cc
  sched.cc
  time.cc
)

set(SOURCES_ASM
  ksys.S
)

add_library(kernel_c_cpp OBJECT ${SOURCES_C_CPP})
add_library(kernel_asm OBJECT ${SOURCES_ASM})

add_library(kernel STATIC
  $<TARGET_OBJECTS:kernel_c_cpp>
  $<TARGET_OBJECTS:kernel_asm>
)

target_link_libraries(kernel PUBLIC
  base
  bindings
)
