#!/bin/bash

function usage() {
    echo "usage: scripts/test.sh [-d|--debug] [-h|--help] [--no-uintr] [-n|--dry-run] [--no-remove] [regex]" >&2
    exit 255
}

NOUINTR=""
REGEX=""
DRY_RUN=""
MODE="Release"
TIMEOUT=240

for arg in "$@"; do
    shift
    case "${arg}" in
        '--help'|'-h') usage ;;
        '--debug'|'-d') MODE="Debug" ;;
        '--no-uintr') NOUINTR="nouintr" ;;
        '--no-remove') REM_FILES="y" ;;
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
    sudo ./iokerneld ias nobw noht no_hw_qdel numanode -1 -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel.log 2>&1 &
    while ! grep -q 'running dataplan' /tmp/iokernel.log; do
      sleep 0.3
      # make sure it is still alive
      pgrep iokerneld > /dev/null || exit 1
      cat /tmp/iokernel.log
    done
    reset
    popd || exit 255
fi

# Run tests
pushd "${TEST_DIR}" || exit 255
export GTEST_COLOR=1
if [ -z "${REGEX}" ]; then
  sudo -E "${CTEST}" ${DRY_RUN} --output-on-failure --verbose --timeout $TIMEOUT
else
  sudo -E "${CTEST}" ${DRY_RUN} --output-on-failure --verbose --timeout $TIMEOUT --tests-regex "${REGEX}"
fi
ec=$?

if [ -z ${REM_FILES} ]; then
  sudo find /tmp -type f \( -name "*.jif" -o -name "*.elf" -o -name "*.jm" -o -name "*.metadata" \) -delete 2> /dev/null
fi

# Stop Caladan
sudo pkill iokerneld
wait
exit $ec
