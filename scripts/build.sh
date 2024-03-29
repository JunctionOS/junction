#!/bin/bash

function usage() {
    echo "usage: scripts/test.sh [-s|--snap-samples] [-p|--permissive-seccomp] [-d|--debug]" >&2
    exit 255
}

SNAP_SAMPLES="OFF"
PERMISSIVE_SECCOMP="OFF"
DEBUG="OFF"
WRITEABLE_LINUX_FS="OFF"

for arg in "$@"; do
    shift
    case "${arg}" in
        '--help'|'-h') usage ;;
        '--snap-samples'|'-s') SNAP_SAMPLES="ON" ;;
        '--permissive-seccomp'|'-p') PERMISSIVE_SECCOMP="ON";;
        '--writeable-linux-fs'|'-w') WRITEABLE_LINUX_FS="ON";;
        '--debug'|'-d') DEBUG="ON";;
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

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

$CMAKE -DWRITEABLE_LINUX_FS="${WRITEABLE_LINUX_FS}" -DPERMISSIVE_SECCOMP="${PERMISSIVE_SECCOMP}" -DSNAPSHOT_SAMPLES="${SNAP_SAMPLES}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" ..
make -j "$(nproc)"
