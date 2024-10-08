include(ExternalProject)
include(ProcessorCount)

message(STATUS "Building caladan")

set(CALADAN_PATH ${CMAKE_SOURCE_DIR}/lib/caladan)

ProcessorCount(NPROC)

ExternalProject_Add(caladan_src
  SOURCE_DIR ${CALADAN_PATH}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} make -j ${NPROC}
  INSTALL_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
)

set(ENV{ROOT_PATH} ${CALADAN_PATH})
execute_process(
  COMMAND make -f ${CALADAN_PATH}/build/shared.mk print-RUNTIME_LIBS
  OUTPUT_VARIABLE CALADAN_RUNTIME_LIBS
)

execute_process(
  COMMAND make -f ${CALADAN_PATH}/build/shared.mk print-LDFLAGS
  OUTPUT_VARIABLE CALADAN_RUNTIME_LDFLAGS
)

string(REPLACE "RUNTIME_LIBS =" " " CALADAN_RUNTIME_LIBS "${CALADAN_RUNTIME_LIBS}")
separate_arguments(CALADAN_RUNTIME_LIBS UNIX_COMMAND "${CALADAN_RUNTIME_LIBS}")

string(REPLACE "LDFLAGS =" " " CALADAN_RUNTIME_LDFLAGS "${CALADAN_RUNTIME_LDFLAGS}")
separate_arguments(CALADAN_RUNTIME_LDFLAGS UNIX_COMMAND "${CALADAN_RUNTIME_LDFLAGS}")

add_library(caladan_runtime STATIC IMPORTED GLOBAL)
add_dependencies(caladan_runtime caladan_src)
set_target_properties(caladan_runtime PROPERTIES IMPORTED_LOCATION ${CALADAN_PATH}/libruntime.a)
target_link_libraries(caladan_runtime INTERFACE "${CALADAN_RUNTIME_LIBS}")
target_link_options(caladan_runtime INTERFACE "${CALADAN_RUNTIME_LDFLAGS}")


ExternalProject_Add(caladan_shim_src
  SOURCE_DIR ${CALADAN_PATH}/shim
  CONFIGURE_COMMAND ""
  BUILD_COMMAND CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} make -j ${NPROC}
  INSTALL_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
)

add_library(caladan_shim STATIC IMPORTED GLOBAL)
add_dependencies(caladan_shim caladan_shim_src caladan_src)
set_target_properties(caladan_shim PROPERTIES IMPORTED_LOCATION ${CALADAN_PATH}/shim/libshim.a)
target_link_options(caladan_shim INTERFACE "-Wl,--wrap=main")
target_link_libraries(caladan_shim INTERFACE "-ldl" caladan_runtime)

set(FLATBUFFERS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flatbuffers")
add_subdirectory(${FLATBUFFERS_SRC_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/flatbuffers-build
  EXCLUDE_FROM_ALL
)
