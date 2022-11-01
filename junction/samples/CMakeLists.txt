message(STATUS "Building junction samples")

# hello_world_native (default glibc, junction and caladan)
add_executable(hello_world_native
  hello_world.cpp
)
target_link_libraries(hello_world_native
  "$<LINK_LIBRARY:WHOLE_ARCHIVE,caladan_shim>"
  junction
  syscall
)

# Paths for linking with custom glibc
set(JUNCTION_LIB_PATH
  ${CMAKE_BINARY_DIR}/src
)
set(GLIBC_BUILD_PATH
  ${CMAKE_SOURCE_DIR}/lib/glibc/build
)
set(LD_LIBRARY_PATH
  ".:${JUNCTION_LIB_PATH}:${CMAKE_CURRENT_BINARY_DIR}:${GLIBC_BUILD_PATH}:${GLIBC_BUILD_PATH}/elf:${GLIBC_BUILD_PATH}/dlfcn:${GLIBC_BUILD_PATH}/nss:${GLIBC_BUILD_PATH}/nis:${GLIBC_BUILD_PATH}/rt:${GLIBC_BUILD_PATH}/resolv:${GLIBC_BUILD_PATH}/mathvec:${GLIBC_BUILD_PATH}/support:${GLIBC_BUILD_PATH}/crypt:${GLIBC_BUILD_PATH}/nptl:/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/lib64"
)
set(DYNAMIC_LINKER_PATH
  "${GLIBC_BUILD_PATH}/elf/ld.so"
)
set(EXEC_ENV
  "GCONV_PATH=${GLIBC_BUILD_PATH}/iconvdata LOCPATH=${GLIBC_BUILD_PATH}/localedata LC_ALL=C"
)
set(EXEC_LOADER_PATH
  "${GLIBC_BUILD_PATH}/elf/ld-linux-x86-64.so.2"
)
set(EXEC_LIBRARY_PATH
  "--library-path ${LD_LIBRARY_PATH}:${CMAKE_BINARY_DIR}:${JUNCTION_LIB_PATH}"
)

# hello_world (with custom glibc, junction and caladan)
add_executable(hello_world
  hello_world.cpp
)
target_link_options(hello_world PUBLIC
  -Wl,--dynamic-linker=${DYNAMIC_LINKER_PATH}
)
target_link_libraries(hello_world
  caladan_shim
  junction
  syscall
)
add_dependencies(hello_world
  generate_runner_script
  move_runner_script
)

# Generate helper script to run in the appropraite custom environment
add_custom_target(generate_runner_script ALL
  /bin/sh "${CMAKE_SOURCE_DIR}/scripts/setup_runner_script.sh" "CUSTOM_LOADER" "${EXEC_ENV}" "${EXEC_LOADER_PATH}" "${EXEC_LIBRARY_PATH}" "hello_world"
  COMMENT "Generating runner script for hello_world"
)
add_custom_target(move_runner_script ALL
  COMMAND mv "${CMAKE_BINARY_DIR}/run_hello_world" "${CMAKE_CURRENT_BINARY_DIR}"
  COMMENT "Move runner script for hello_world"
  DEPENDS generate_runner_script
)

# Generate inputs for the program
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test.txt "foo")
