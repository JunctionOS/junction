message(STATUS "Building junction snapshot")

set(SOURCES_C_CPP
  snapshot.cc
  snapshot_elf.cc
)

add_library(snapshot_c_cpp OBJECT ${SOURCES_C_CPP})

add_library(snapshot STATIC
  $<TARGET_OBJECTS:snapshot_c_cpp>
)
