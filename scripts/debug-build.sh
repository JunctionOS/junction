#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
BUILD_DIR=${ROOT_DIR}/build-debug
BIN_DIR=${ROOT_DIR}/bin
CMAKE=${BIN_DIR}/bin/cmake

. ${SCRIPT_DIR}/submodule_check.sh

mkdir -p $BUILD_DIR
cd $BUILD_DIR

$CMAKE -DCMAKE_BUILD_TYPE=Debug ..
make -j `nproc`
