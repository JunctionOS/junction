message(STATUS "Building junction filesystem")

add_library(fs
  core.cc
  dev.cc
  file.cc
  linuxfs/dir.cc
  linuxfs/linuxfile.cc
  linuxfs/linuxfs.cc
  memfs/memfs.cc
  memfs/dir.cc
)

target_link_libraries(fs
  base
  bindings
  kernel
)
