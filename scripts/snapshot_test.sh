#!/bin/bash

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
${SCRIPT_DIR}/test.sh 'c_hello|python_hello'
