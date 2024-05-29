#!/bin/bash

function usage() {
    echo "usage: scripts/test.sh [-d|--debug] [-h|--help] [--no-uintr] [-n|--dry-run] [regex]" >&2
    exit 255
}

NOUINTR=""
REGEX=""
DRY_RUN=""
MODE="Release"

for arg in "$@"; do
    shift
    case "${arg}" in
        '--help'|'-h') usage ;;
        '--debug'|'-d') MODE="Debug" ;;
        '--no-uintr') NOUINTR="nouintr" ;;
        '-n'|'--dry-run') DRY_RUN="--show-only" ;;
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

# Start Caladan if not doing a dry run

if [[ -z ${DRY_RUN} ]]; then
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
fi

# Run tests
pushd "${TEST_DIR}" || exit 255
export GTEST_COLOR=1
if [ "${REGEX}" = "" ]; then
  sudo "${CTEST}" ${DRY_RUN} --output-on-failure --verbose --timeout 120
else
  sudo "${CTEST}" ${DRY_RUN} --output-on-failure --verbose --timeout 120 --tests-regex "${REGEX}"
fi
ec=$?


# Stop Caladan
sudo pkill iokerneld
wait
exit $ec
