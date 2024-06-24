message(STATUS "Building junction snapshot C samples")

# exercise things
add_executable(st_catch_all
	st_catch_all.cc
)

add_executable(st_empty
	st_empty.cc
)

add_executable(st_epoll
	st_epoll.cc
)

add_executable(st_linux_file
	st_linux_file.cc
)

add_executable(st_memfs_file
	st_memfs_file.cc
)

add_executable(st_pipe
	st_pipe.cc
)

add_executable(st_socketpair
  st_socketpair.cc
)

add_executable(st_device
  st_device.cc
)

add_executable(st_stdio_file
	st_stdio_file.cc
)

add_executable(mt_simple
	mt_simple.cc
)

add_executable(yes
	yes.cc
)

# tests

# st_empty
add_test(
  NAME c_st_empty_snapshot
  COMMAND sh -c "rm -f /tmp/st_empty.metadata /tmp/st_empty.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_empty --\
  $<TARGET_FILE:st_empty>"
)

add_test(
  NAME c_st_empty_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_empty.metadata /tmp/st_empty.elf"
)

# st_epoll
add_test(
  NAME c_st_epoll_snapshot
  COMMAND sh -c "rm -f /tmp/st_epoll.metadata /tmp/st_epoll.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_epoll --\
  $<TARGET_FILE:st_epoll>"
)

add_test(
  NAME c_st_epoll_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_epoll.metadata /tmp/st_epoll.elf"
)

# st_linux_file
add_test(
  NAME c_st_linux_file_snapshot
  COMMAND sh -c "rm -f /tmp/st_linux_file.metadata /tmp/st_linux_file.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_linux_file --\
  $<TARGET_FILE:st_linux_file>"
)

add_test(
  NAME c_st_linux_file_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_linux_file.metadata /tmp/st_linux_file.elf"
)

# st_pipe
add_test(
  NAME c_st_pipe_snapshot
  COMMAND sh -c "rm -f /tmp/st_pipe.metadata /tmp/st_pipe.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_pipe --\
  $<TARGET_FILE:st_pipe>"
)

add_test(
  NAME c_st_pipe_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_pipe.metadata /tmp/st_pipe.elf"
)

# st_socketpair
add_test(
  NAME c_st_socketpair_snapshot
  COMMAND sh -c "rm -f /tmp/st_socketpair.metadata /tmp/st_socketpair.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_socketpair --\
  $<TARGET_FILE:st_socketpair>"
)

add_test(
  NAME c_st_socketpair_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_socketpair.metadata /tmp/st_socketpair.elf"
)

add_test(
  NAME c_st_device_snapshot
  COMMAND sh -c "rm -f /tmp/st_device.metadata /tmp/st_device.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_device --\
  $<TARGET_FILE:st_device>"
)

add_test(
  NAME c_st_device_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_device.metadata /tmp/st_device.elf"
)

# st_stdio_file
add_test(
  NAME c_st_stdio_file_snapshot
  COMMAND sh -c "rm -f /tmp/st_stdio_file.metadata /tmp/st_stdio_file.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/st_stdio_file --\
  $<TARGET_FILE:st_stdio_file>"
)

add_test(
  NAME c_st_stdio_file_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/st_stdio_file.metadata /tmp/st_stdio_file.elf"
)

# mt_simple
add_test(
  NAME mt_simple_snapshot
  COMMAND sh -c "rm -f /tmp/mt_simple.metadata /tmp/mt_simple.elf && $<TARGET_FILE:junction_run> ${caladan_test_config_path} -S --snapshot-prefix /tmp/mt_simple --\
  $<TARGET_FILE:mt_simple>"
)

add_test(
  NAME mt_simple_restore
  COMMAND sh -c "$<TARGET_FILE:junction_run> ${caladan_test_config_path} -r --\
  /tmp/mt_simple.metadata /tmp/mt_simple.elf"
)
