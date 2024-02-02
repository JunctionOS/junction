#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

export DEBIAN_FRONTEND=noninteractive

# Install Linux packages
sudo apt update
sudo -E apt install -y perl libboost-dev libboost-program-options-dev bison gcc-12 g++-12 gawk
sudo -E apt install -y clang-tidy-16 clang-format-16 || true

# Initialize submodules
git submodule update --init --recursive --jobs=`nproc`

# Install modules
cd $SCRIPT_DIR
./install_cereal.sh
./install_cmake.sh
./install_caladan.sh
./install_glibc.sh
