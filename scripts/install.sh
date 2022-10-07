#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

# Install Linux packages
sudo apt update
sudo apt install -y clang-format \
                    libspdlog-dev

# Initialize submodules
git submodule update --init --recursive

# Install modules
cd $SCRIPT_DIR
./install_cmake.sh
./install_caladan.sh
./install_syscall_intercept.sh