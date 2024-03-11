#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/../
CODE_DIR=${ROOT_DIR}/junction

# style is based on Google's style, defined in the .clang-format file
find "${CODE_DIR}" -iname '*.h' -o -iname '*.cc' | xargs clang-format-16 -i
