#!/bin/bash
set -x

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
(sudo pkill iokerneld && sleep 2) || true
sudo scripts/setup_machine.sh nouintr
sudo ./iokerneld simple nobw noht no_hw_qdel -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel.log 2>&1 &
iok_pid=$!
while ! grep -q 'running dataplan' /tmp/iokernel.log; do
  sleep 0.3
  # make sure it is still alive
  pgrep iokerneld > /dev/null
done
reset

# Prepare test environment
rm -rf /tmp/junction
mkdir /tmp/junction

# Run tests
cd $TEST_DIR
export GTEST_COLOR=1
sudo $CTEST --output-on-failure --verbose --timeout 120

# Cleanup test state
rm -rf /tmp/junction

# Stop Caladan
sudo pkill iokerneld
wait
exit 0
