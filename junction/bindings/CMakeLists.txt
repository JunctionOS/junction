message(STATUS "Building junction bindings")

add_library(bindings
  log.cc
  runtime.cc
  sync.cc
  thread.cc
  timer.cc
  switch.S
)

target_link_libraries(bindings
  base
  caladan_runtime
)

add_executable(test
  test.cc
)

target_link_libraries(test
  bindings
)
