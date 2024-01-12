message(STATUS "Building junction kernel")

set(SOURCES_C_CPP
  elf.cc
  eventfd.cc
  exec.cc
  file.cc
  futex.cc
  itimer.cc
  misc.cc
  mm.cc
  pipe.cc
  poll.cc
  proc.cc
  random.cc
  sched.cc
  sigframe.cc
  signal.cc
  stdiofile.cc
  time.cc
  trapframe.cc
)

set(SOURCES_ASM
  exec.S
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
  snapshot
)
