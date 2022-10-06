#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
BUILD_DIR=${ROOT_DIR}/build
TEST_DIR=${BUILD_DIR}/test
BIN_DIR=${ROOT_DIR}/bin
CTEST=${BIN_DIR}/bin/ctest

cd $TEST_DIR

export GTEST_COLOR=1
$CTEST --output-on-failure --verbose --timeout 120