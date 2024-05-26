#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/../
FLATBUFFERS_DIR="${ROOT_DIR}/lib/flatbuffers"

cd "$(dirname "${FLATBUFFERS_DIR}")"
git submodule update --init --recursive -f flatbuffers
