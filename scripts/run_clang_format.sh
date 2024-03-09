#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/../
CODE_DIR=${ROOT_DIR}/junction

find "${CODE_DIR}" -iname '*.h' -o -iname '*.cc' | xargs clang-format-16 -i
