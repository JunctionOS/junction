#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/../
JIFTOOLS_DIR="${ROOT_DIR}/lib/jiftools"

cd "$(dirname "${JIFTOOLS_DIR}")"
git submodule update --init --recursive -f jiftools

cd jiftools
