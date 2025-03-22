cmake_minimum_required(VERSION 3.24)

find_program(CMAKE_C_COMPILER NAMES gcc-13 gcc-12 gcc)
find_program(CMAKE_CXX_COMPILER NAMES g++-13 g++-12 g++)

if (CMAKE_C_COMPILER AND CMAKE_CXX_COMPILER)
    set(CMAKE_C_COMPILER ${CMAKE_C_COMPILER} CACHE PATH "C compiler" FORCE)
    set(CMAKE_CXX_COMPILER ${CMAKE_CXX_COMPILER} CACHE PATH "C++ compiler" FORCE)
else()
    message(FATAL_ERROR "No suitable GCC compiler found")
endif()

project(junction C CXX ASM)

# Check if the compiler is GNU
if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "This project requires GCC as the C compiler.")
endif()

# Check GCC version
if(CMAKE_C_COMPILER_VERSION VERSION_LESS 12.0)
    message(FATAL_ERROR "GCC version 12 or higher is required. Detected version: ${CMAKE_C_COMPILER_VERSION}")
endif()


message(STATUS "Building junction")

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_ENABLE_EXPORTS ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
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
    GIT_TAG v0.5.1 # Optionally specify a commit hash, version tag or branch here
)
# Set any global configuration variables such as `Rust_TOOLCHAIN` before this line!
FetchContent_MakeAvailable(Corrosion)

if(SNAPSHOT_SAMPLES)
    corrosion_import_crate(MANIFEST_PATH ${CMAKE_SOURCE_DIR}/lib/jiftools/Cargo.toml)
endif()

set(READJIF ${CMAKE_BINARY_DIR}/readjif)
set(JIFTOOL ${CMAKE_BINARY_DIR}/jiftool)

include_directories(
  ${CMAKE_SOURCE_DIR}
  SYSTEM ${CMAKE_SOURCE_DIR}/lib/caladan/inc
  SYSTEM ${CMAKE_SOURCE_DIR}/lib/cereal/include
  SYSTEM ${CMAKE_SOURCE_DIR}/lib/flatbuffers/include
)

add_subdirectory(lib)
add_subdirectory(junction)
add_subdirectory(junction-ctl)
