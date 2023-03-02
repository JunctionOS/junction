#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

# Install Linux packages
sudo apt update
sudo apt install -y clang-format clang-tidy perl libboost-dev libboost-program-options-dev bison gcc-12 g++-12 gawk

# From caladan README
sudo apt install -y make cmake pkg-config libnl-3-dev libnl-route-3-dev libnuma-dev uuid-dev libssl-dev libaio-dev libcunit1-dev libclang-dev libncurses-dev meson python3-pyelftools

# Initialize submodules
git submodule update --init --recursive

# Install modules
cd $SCRIPT_DIR
./install_cmake.sh
./install_caladan.sh
./install_glibc.sh
