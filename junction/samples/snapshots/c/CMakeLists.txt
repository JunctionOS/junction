message(STATUS "Building junction snapshot C samples")

set(tests
    "st_catch_all"
    "st_empty"
    "st_epoll"
    "st_linux_file"
    "st_memfs_file"
    "st_pipe"
    "st_socketpair"
    "st_device"
    "st_stdio_file"
    "mt_simple"
)

foreach(test ${tests})
  add_executable(${test}
    ${test}.cc
  )

  add_snapshot_restore_test(${test} "$<TARGET_FILE:${test}>")
endforeach()

add_executable(yes
	yes.cc
)