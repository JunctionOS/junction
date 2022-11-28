
# Outputs shimjmp_tbl.cpp to build/junction/shim/shimjmp_tbl.cpp
add_custom_command(
    OUTPUT  shimjmp_tbl.cpp intercept.S
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/shimjmp_tbl.py
      ${CMAKE_CURRENT_SOURCE_DIR}/shim.h
      ${CMAKE_CURRENT_BINARY_DIR}/shimjmp_tbl.cpp
      ${CMAKE_CURRENT_BINARY_DIR}/intercept.S
    DEPENDS shimjmp_tbl.py shim.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set(CMAKE_ASM_FLAGS "${ASM_FLAGS} -Wa,--noexecstack")

add_library(shim_preload SHARED
  preload/thread.cc
  intercept.S
)

add_library(glibc_shim_backend
  backend/init.cc
  backend/sem.cc
  backend/sync.cc
  backend/thread.cc
  shimjmp_tbl.cpp
)
