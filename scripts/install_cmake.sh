#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
BIN_DIR=${ROOT_DIR}/bin

mkdir -p $BIN_DIR
cd $BIN_DIR

# Install a specific version of cmake
wget https://github.com/Kitware/CMake/releases/download/v3.24.2/cmake-3.24.2-linux-x86_64.sh
chmod +x cmake-3.24.2-linux-x86_64.sh
./cmake-3.24.2-linux-x86_64.sh --skip-license
rm cmake-3.24.2-linux-x86_64.sh