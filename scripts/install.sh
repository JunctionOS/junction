#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

. "${SCRIPT_DIR}"/helpers.sh

# Install Linux packages
install_missing_packages perl libboost-dev libboost-program-options-dev bison gcc-12 g++-12 gawk binutils yapf3 libfmt-dev libcap-dev python3-termcolor
install_missing_packages clang-tidy-16 clang-format-16 || true

# Install packages for nbody tests and samples
install_missing_packages gfortran php-cli golang-go python3-numpy openjdk-21-jre-headless nodejs python3-pil ruby npm

# Initialize submodules
git submodule update --init --recursive --jobs=`nproc`

# Install modules
cd $SCRIPT_DIR
./install_cereal.sh
./install_cmake.sh
./install_caladan.sh
./install_glibc.sh
./install_flatbuffers.sh

touch ${ROOT_DIR}/.install_script_ran

#./install_function_bench.sh
