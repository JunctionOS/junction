#!/bin/bash
set -xe

# Globals
CODE_DIR=junction

find ${CODE_DIR} -name '*.cc' | xargs run-clang-tidy -j12 -p build -header-filter=".*" -extra-arg=-std=gnu++20 -config-file .clang-tidy
