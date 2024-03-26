#!/bin/bash

function usage() {
    echo "usage: scripts/test.sh [-d|--debug] [-h|--help] [--no-uintr] [regex]" >&2
    exit 255
}

NOUINTR=""
REGEX=""
MODE="Release"

for arg in "$@"; do
    shift
    case "${arg}" in
        '--help'|'-h') usage ;;
        '--debug'|'-d') MODE="Debug" ;;
        '--no-uintr') NOUINTR="nouintr" ;;
        *)
            if [[ -z ${REGEX} ]]; then
                REGEX=${arg}
            else
                usage
            fi;;
    esac
done

set -x

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/../
if [[ "${MODE}" == "Release" ]] ; then
    BUILD_DIR=${ROOT_DIR}/build
else
    BUILD_DIR=${ROOT_DIR}/build-debug
fi
CALADAN_DIR=${ROOT_DIR}/lib/caladan
TEST_DIR=${BUILD_DIR}/junction
BIN_DIR=${ROOT_DIR}/bin
CTEST=${BIN_DIR}/bin/ctest

# Start Caladan
pushd "${CALADAN_DIR}" || exit 255
(sudo pkill iokerneld && sleep 2) || true
sudo scripts/setup_machine.sh ${NOUINTR}
sudo ./iokerneld ias nobw noht no_hw_qdel -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel.log 2>&1 &
while ! grep -q 'running dataplan' /tmp/iokernel.log; do
  sleep 0.3
  # make sure it is still alive
  pgrep iokerneld > /dev/null
done
reset
popd || exit 255

# Run tests
pushd "${TEST_DIR}" || exit 255
export GTEST_COLOR=1
if [ "${REGEX}" = "" ]; then
  sudo "${CTEST}" --output-on-failure --verbose --timeout 120
else
  sudo "${CTEST}" --output-on-failure --verbose --timeout 120 --tests-regex "${REGEX}"
fi

# Stop Caladan
sudo pkill iokerneld
wait
exit 0
