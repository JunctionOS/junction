message(STATUS "Building junction control server")

set(SOURCES_C_CPP
  webctl.cc
)

add_library(control_c_cpp OBJECT ${SOURCES_C_CPP})

add_library(control STATIC
  $<TARGET_OBJECTS:control_c_cpp>
)
