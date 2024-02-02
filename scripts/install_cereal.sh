#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CEREAL_DIR="${ROOT_DIR}/lib/cereal"

cd ${CEREAL_DIR}/..
git submodule update --init --recursive -f cereal
