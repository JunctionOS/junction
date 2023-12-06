message(STATUS "Building junction snapshot samples")

# snapshot entrypoint
add_executable(entrypoint
  entrypoint.cc
)

# snapshot multiple calls
add_executable(repeated_snapshot
  repeated_snapshot.cc
)
