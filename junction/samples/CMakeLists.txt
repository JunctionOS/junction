message(STATUS "Building junction samples")

# hello_world_native (default glibc, junction and caladan)
add_executable(hello_world_native
  hello_world.cpp
)
target_link_libraries(hello_world_native
  junction
)

# Paths for linking with custom glibc
set(JUNCTION_LIB_PATH
  ${CMAKE_BINARY_DIR}/src
)
set(GLIBC_BUILD_PATH
  ${CMAKE_SOURCE_DIR}/lib/glibc/build
)
set(OPT_RPATH
  "-Wl,-rpath,.,-rpath,${JUNCTION_LIB_PATH},-rpath,${CMAKE_CURRENT_BINARY_DIR},-rpath,${GLIBC_BUILD_PATH},-rpath,${GLIBC_BUILD_PATH}/elf,-rpath,${GLIBC_BUILD_PATH}/dlfcn,-rpath,${GLIBC_BUILD_PATH}/nss,-rpath,${GLIBC_BUILD_PATH}/nis,-rpath,${GLIBC_BUILD_PATH}/rt,-rpath,${GLIBC_BUILD_PATH}/resolv,-rpath,${GLIBC_BUILD_PATH}/mathvec,-rpath,${GLIBC_BUILD_PATH}/support,-rpath,${GLIBC_BUILD_PATH}/crypt,-rpath,${GLIBC_BUILD_PATH}/nptl,-rpath,/usr/lib/x86_64-linux-gnu,-rpath,/lib/x86_64-linux-gnu,-rpath,/lib64"
)
set(OPT_DYNAMIC_LINKER_PATH
  "-Wl,--dynamic-linker=${GLIBC_BUILD_PATH}/elf/ld.so"
)

# hello_world (with custom glibc, junction and caladan)
add_executable(hello_world
  hello_world.cpp
)
target_link_options(hello_world PUBLIC
  ${OPT_RPATH}
  ${OPT_DYNAMIC_LINKER_PATH}
)
target_link_libraries(hello_world
  junction
)

# Generate inputs for the program
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test.txt "foo")
