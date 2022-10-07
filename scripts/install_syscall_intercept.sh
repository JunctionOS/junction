#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
SYSCALL_INTERCEPT_DIR=${ROOT_DIR}/lib/syscall_intercept
SYSCALL_INTERCEPT_INSTALL_DIR=${SYSCALL_INTERCEPT_DIR}/install

# Create installation directory
mkdir -p $SYSCALL_INTERCEPT_INSTALL_DIR

cd $SYSCALL_INTERCEPT_INSTALL_DIR

# Install syscall_intercept
cmake $SYSCALL_INTERCEPT_DIR -DCMAKE_INSTALL_PREFIX=. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc
make
make install