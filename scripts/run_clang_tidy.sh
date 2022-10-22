#!/bin/bash
set -xe

# Globals
CODE_DIR=junction

find ${CODE_DIR} -name '*.cc' | xargs clang-tidy -p build -header-filter=".*" -extra-arg=-std=gnu++20 --config-file=.clang-tidy
