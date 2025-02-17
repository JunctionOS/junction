include(ExternalProject)
include(ProcessorCount)

message(STATUS "Building caladan")

set(CALADAN_PATH ${CMAKE_SOURCE_DIR}/lib/caladan)

ProcessorCount(NPROC)

ExternalProject_Add(caladan_src
  SOURCE_DIR ${CALADAN_PATH}
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
  JOB_SERVER_AWARE 1
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  ExternalProject_Add_Step(caladan_src prebuild1
    COMMAND grep -q CONFIG_DEBUG=n ${CALADAN_PATH}/build/config || sed "s/CONFIG_DEBUG.*/CONFIG_DEBUG=n/g" -i ${CALADAN_PATH}/build/config
    DEPENDERS build
    ALWAYS 1
  )
  ExternalProject_Add_Step(caladan_src prebuild2
    COMMAND grep -q CONFIG_OPTIMIZE=y ${CALADAN_PATH}/build/config || sed "s/CONFIG_OPTIMIZE.*/CONFIG_OPTIMIZE=y/g" -i ${CALADAN_PATH}/build/config
    DEPENDERS build
    ALWAYS 1
  )
else()
  ExternalProject_Add_Step(caladan_src prebuild1
    COMMAND grep -q CONFIG_DEBUG=y ${CALADAN_PATH}/build/config || sed "s/CONFIG_DEBUG.*/CONFIG_DEBUG=y/g" -i ${CALADAN_PATH}/build/config
    DEPENDERS build
    ALWAYS 1
  )
  ExternalProject_Add_Step(caladan_src prebuild2
    COMMAND grep -q CONFIG_OPTIMIZE=n ${CALADAN_PATH}/build/config || sed "s/CONFIG_OPTIMIZE.*/CONFIG_OPTIMIZE=n/g" -i ${CALADAN_PATH}/build/config
    DEPENDERS build
    ALWAYS 1
  )
endif()

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
  INSTALL_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
  JOB_SERVER_AWARE 1
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
