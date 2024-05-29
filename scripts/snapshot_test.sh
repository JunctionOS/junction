#!/bin/bash

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
${SCRIPT_DIR}/test.sh '(snapshot)|(restore)'
