#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
CODE_DIR=${SCRIPT_DIR}/../junction

find ${CODE_DIR} -iname *.h -o -iname *.cc | xargs clang-format -style=Google -i
