#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
BUILD_DIR=${ROOT_DIR}/build
BIN_DIR=${ROOT_DIR}/bin
CMAKE=${BIN_DIR}/cmake-3.24.2-linux-x86_64/bin/cmake

# Run clang-format
# TODO(gohar): This is giving issues with likely/unlikely indentation.
# find ${ROOT_DIR}/src -iname *.h -o -iname *.cpp -o -iname *.c -o -iname *.h | xargs clang-format -i
# find ${ROOT_DIR}/inc -iname *.h -o -iname *.cpp -o -iname *.c -o -iname *.h | xargs clang-format -i
# find ${ROOT_DIR}/test -iname *.h -o -iname *.cpp -o -iname *.c -o -iname *.h | xargs clang-format -i

mkdir -p $BUILD_DIR
cd $BUILD_DIR

$CMAKE \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  ..
make -j `nproc`