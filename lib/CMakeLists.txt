include(ExternalProject)

message(STATUS "Building caladan")

set(CALADAN_PATH ${CMAKE_SOURCE_DIR}/lib/caladan)

ExternalProject_Add(caladan
  SOURCE_DIR ${CALADAN_PATH}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND "make"
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
add_dependencies(caladan_runtime caladan)
set_target_properties(caladan_runtime PROPERTIES IMPORTED_LOCATION ${CALADAN_PATH}/libruntime.a)
target_link_libraries(caladan_runtime INTERFACE "${CALADAN_RUNTIME_LIBS}")
target_link_options(caladan_runtime INTERFACE "${CALADAN_RUNTIME_LDFLAGS}")
