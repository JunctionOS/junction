#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CALADAN_DIR=${ROOT_DIR}/lib/caladan

# Install Linux packages
sudo apt install -y make gcc cmake pkg-config libnl-3-dev libnl-route-3-dev libnuma-dev uuid-dev libssl-dev libaio-dev libcunit1-dev libclang-dev libncurses-dev meson python3-pyelftools

cd $CALADAN_DIR

# Install Caladan
#curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=nightly
#source $HOME/.cargo/env

make submodules
(cd ksched && make -j `nproc`)

## Install load-generator app
#cd apps/synthetic
#cargo build --release
