#!/bin/bash

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CALADAN_DIR=${ROOT_DIR}/lib/caladan
BUILD_DIR=${ROOT_DIR}/build/junction
SAMPLES_DIR=${BUILD_DIR}/samples/snapshots
JUNCTION=${BUILD_DIR}/junction_run
METADATA=/tmp/snapshot.metadata
ELF=/tmp/snapshot.elf
SNAPSHOT="${METADATA} ${ELF}"
CFG=${BUILD_DIR}/caladan_test.config
JUNCTION_RUN="${JUNCTION} ${CFG} --"
JUNCTION_RESTORE="${JUNCTION} ${CFG} -r -- ${SNAPSHOT}"

# Start Caladan
pushd $CALADAN_DIR
(sudo pkill iokerneld && sleep 2) || true
sudo scripts/setup_machine.sh
sudo ./iokerneld simple nobw noht no_hw_qdel -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel.log 2>&1 &
iok_pid=$!
while ! grep -q 'running dataplan' /tmp/iokernel.log; do
  sleep 0.3
  # make sure it is still alive
  pgrep iokerneld > /dev/null
done
reset
popd

run_test() {
    $JUNCTION_RUN $@ | grep --color -i -e snapshot -e "unexpected signal"
    $JUNCTION_RESTORE | grep --color -i restore
    rm ${SNAPSHOT}
}

rm -rf ${SNAPSHOT}

# Run C hello world example
echo "Running C hello world test:"
run_test ${SAMPLES_DIR}/c/entrypoint ${SNAPSHOT}

echo "Running Python hello world test:"
# Run Python hello world example
run_test $(which python) ${SAMPLES_DIR}/python/hello.py snap ${SNAPSHOT}

