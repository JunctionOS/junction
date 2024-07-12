
message(STATUS "Building nbody...")

## Rust
set(nbody_rust "${CMAKE_CURRENT_BINARY_DIR}/nbody_rust")
add_custom_command(
	OUTPUT ${nbody_rust}
	COMMAND rustc -O ${CMAKE_CURRENT_SOURCE_DIR}/nbody.rs -o ${nbody_rust}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/nbody.rs
	COMMENT "Building Rust nbody"
)
add_custom_target(nbody_rust_bin ALL
  DEPENDS ${nbody_rust})


## C++
add_executable(nbody_cc
	nbody.cc
)

## Go
set(nbody_go "${CMAKE_CURRENT_BINARY_DIR}/nbody_go")
add_custom_command(
  OUTPUT ${nbody_go}
  COMMAND go build -o ${nbody_go} ${CMAKE_CURRENT_SOURCE_DIR}/nbody_go.go
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/nbody_go.go
  COMMENT "Building Go nbody"
)
add_custom_target(nbody_go_bin ALL
  DEPENDS ${nbody_go})

## Fortran
project(nbody LANGUAGES Fortran)
add_executable(nbody_fortran
	nbody.f90
)

# Tests
find_package(Java REQUIRED COMPONENTS Runtime)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Perl REQUIRED)
find_package(Ruby)

set(NODE_BIN "/usr/bin/node")
set(PHP_BIN "/usr/bin/php")


set(NBODY_N "100000")
test_bin(nbody_cc "$<TARGET_FILE:nbody_cc> ${NBODY_N}")
test_bin(nbody_go "${nbody_go} ${NBODY_N}")
test_bin(nbody_rust "${nbody_rust} ${NBODY_N}")
test_bin(nbody_fortran "$<TARGET_FILE:nbody_fortran> ${NBODY_N}")
test_bin(nbody_java "${Java_JAVA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/nbody.java ${NBODY_N}")
test_bin(nbody_js "${NODE_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/nbody.js ${NBODY_N}")
test_bin(nbody_python "${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/nbody.py ${NBODY_N}")
test_bin(nbody_perl "${PERL_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/nbody.pl ${NBODY_N}")
test_bin(nbody_ruby "${Ruby_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/nbody.ruby ${NBODY_N}")
test_bin(nbody_php "${PHP_BIN} -n ${CMAKE_CURRENT_SOURCE_DIR}/nbody.php ${NBODY_N}")
