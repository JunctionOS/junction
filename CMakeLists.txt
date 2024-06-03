cmake_minimum_required(VERSION 3.24)
project(junction C CXX ASM)

message(STATUS "Building junction")

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_ENABLE_EXPORTS ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "${CFLAGS} ${ASM_OPTIONS}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -g -fno-stack-protector -march=native -m64 -muintr -mxsavec")
set(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O3 -flto=auto -ffast-math -fconcepts-diagnostics-depth=100")

# Add corrosion: a way to build rust code in Cmake
include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.4 # Optionally specify a commit hash, version tag or branch here
)
# Set any global configuration variables such as `Rust_TOOLCHAIN` before this line!
FetchContent_MakeAvailable(Corrosion)

include_directories(
  ${CMAKE_SOURCE_DIR}
  SYSTEM ${CMAKE_SOURCE_DIR}/lib/caladan/inc
  SYSTEM ${CMAKE_SOURCE_DIR}/lib/cereal/include
  SYSTEM ${CMAKE_SOURCE_DIR}/lib/flatbuffers/include
)

add_subdirectory(lib)
add_subdirectory(junction)
add_subdirectory(junction-ctl)
