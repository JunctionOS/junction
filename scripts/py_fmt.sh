#!/bin/bash
set -xe

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
autopep8 -i -aa  ${SCRIPT_DIR}/benchmark.py
