#!/bin/bash

function usage() {
    echo "usage: scripts/test.sh [-s|--snap-samples] [-p|--permissive-seccomp] [-d|--debug]" >&2
    exit 255
}

SNAP_SAMPLES="OFF"
PERMISSIVE_SECCOMP="OFF"
DEBUG="OFF"
WRITEABLE_LINUX_FS="OFF"
CI="OFF"

for arg in "$@"; do
    shift
    case "${arg}" in
        '--help'|'-h') usage ;;
        '--snap-samples'|'-s') SNAP_SAMPLES="ON" ;;
        '--permissive-seccomp'|'-p') PERMISSIVE_SECCOMP="ON";;
        '--writeable-linux-fs'|'-w') WRITEABLE_LINUX_FS="ON";;
        '--debug'|'-d') DEBUG="ON";;
        '--ci'|'-c') CI="ON";; 
    esac
done

set -xe

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/../
if [ "${DEBUG}" = "ON" ];
then
    BUILD_TYPE=Debug
    BUILD_DIR=${ROOT_DIR}/build-debug
else
    BUILD_TYPE=Release
    BUILD_DIR=${ROOT_DIR}/build
fi
BIN_DIR=${ROOT_DIR}/bin
CMAKE=${BIN_DIR}/bin/cmake

. "${SCRIPT_DIR}"/submodule_check.sh

if [ "$SNAP_SAMPLES" = "ON" ] && [ ! -f "${ROOT_DIR}/.function_bench_installed" ]; then
    set +x
	echo -n -e "$RED"
    echo "Snapshot samples require Function Bench to be installed. Please run scripts/install_function_bench.sh first."
    echo -e "$NC"
    exit 1
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

CMAKE_ARGS="-DWRITEABLE_LINUX_FS=${WRITEABLE_LINUX_FS} \
            -DPERMISSIVE_SECCOMP=${PERMISSIVE_SECCOMP} \
            -DSNAPSHOT_SAMPLES=${SNAP_SAMPLES} \
            -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."

if [ "${CI}" = "ON" ]; then
    echo "CI MODE: using gcc 12 explicitly."
    CMAKE_ARGS="-D CMAKE_C_COMPILER=gcc-12 \
                -D CMAKE_CXX_COMPILER=g++-12 \
                ${CMAKE_ARGS}"
fi

$CMAKE $CMAKE_ARGS
make -j "$(nproc)"
