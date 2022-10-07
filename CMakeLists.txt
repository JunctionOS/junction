cmake_minimum_required(VERSION 3.21)
project(junction)

message(STATUS "Building junction")

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 20)
set(THREADS_PREFER_PTHREAD_FLAG ON)

if(NOT TARGET spdlog)
  find_package(spdlog REQUIRED)
endif()

add_subdirectory(src)
add_subdirectory(test)