#!/bin/bash
set -xe

# Check flags
CI_MODE=false
if [ "$1" == "--ci" ]; then
    CI_MODE=true
    echo "Running in CI mode"
fi

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

export DEBIAN_FRONTEND=noninteractive

# Install Linux packages
sudo apt update
sudo -E apt install -y perl libboost-dev libboost-program-options-dev bison gcc-12 g++-12 gawk binutils yapf3 libfmt-dev libcap-dev python3-termcolor
sudo -E apt install -y clang-tidy-16 clang-format-16 || true

# Install packages for nbody tests and samples
sudo -E apt install -y gfortran php-cli golang-go python3-numpy openjdk-21-jre-headless nodejs python3-pil ruby npm

# Initialize submodules
git submodule update --init --recursive --jobs=`nproc`

# Install modules
cd $SCRIPT_DIR
./install_cereal.sh
./install_cmake.sh
if [ "$CI_MODE" = true ]; then
    ./install_caladan.sh --ci
else
    ./install_caladan.sh
fi
./install_glibc.sh
./install_flatbuffers.sh

touch ${ROOT_DIR}/.install_script_ran

if [ "$CI_MODE" = false ]; then
    ./install_function_bench.sh
fi
