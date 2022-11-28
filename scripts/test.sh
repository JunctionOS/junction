#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
BUILD_DIR=${ROOT_DIR}/build
CALADAN_DIR=${ROOT_DIR}/lib/caladan
TEST_DIR=${BUILD_DIR}/junction
BIN_DIR=${ROOT_DIR}/bin
CTEST=${BIN_DIR}/bin/ctest

# Start Caladan
cd $CALADAN_DIR
sudo scripts/setup_machine.sh
sudo ./iokerneld simple nobw noht no_hw_qdel -- --allow 00:00.0 --vdev=net_tap0 &
iok_pid=$!
sleep 3
reset

# Run tests
cd $TEST_DIR
export GTEST_COLOR=1
$CTEST --output-on-failure --verbose --timeout 120

# Stop Caladan
sudo pkill iokerneld
wait
exit 0
