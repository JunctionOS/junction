message(STATUS "Building junction filesystem")

set(SOURCES_C_CPP
  core.cc
)

add_library(fs_c_cpp OBJECT ${SOURCES_C_CPP})

add_library(fs STATIC
  $<TARGET_OBJECTS:fs_c_cpp>
)

target_link_libraries(fs PUBLIC
  base
  bindings
  kernel
)
