#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

# Install Linux packages
sudo apt update
sudo apt install -y clang-format \
                    cmake

# Initialize submodules
git submodule update --init --recursive

./install_caladan.sh
