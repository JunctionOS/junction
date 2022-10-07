message(STATUS "Building junction src")

include(FindPkgConfig)

pkg_check_modules(CAPSTONE REQUIRED capstone)
find_library(SYSCALL_INTERCEPT_LIB libsyscall_intercept.a ${CMAKE_SOURCE_DIR}/lib/syscall_intercept/install/lib)
find_package(Threads REQUIRED)

include_directories(
  ${CMAKE_SOURCE_DIR}/lib/syscall_intercept/install/include
  ${CMAKE_SOURCE_DIR}/inc
)

add_library(junction SHARED
  syscall/handlers.cpp
  syscall/intercept.c

  filesystem/file.cpp
  filesystem/filesystem.cpp

  memorysystem/memorysystem.cpp
)

target_link_libraries(junction
  ${SYSCALL_INTERCEPT_LIB}
  ${CAPSTONE_LIBRARIES}
  ${CMAKE_DL_LIBS}
  Threads::Threads
  spdlog::spdlog
)