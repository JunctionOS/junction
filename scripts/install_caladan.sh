#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CALADAN_DIR=${ROOT_DIR}/lib/caladan
CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan

# Install Linux packages
sudo -E apt install -y make cmake pkg-config libnl-3-dev libnl-route-3-dev libnuma-dev uuid-dev libssl-dev libaio-dev libcunit1-dev libclang-dev libncurses-dev meson python3-pyelftools

# Apply patches
cd $CALADAN_DIR
for patch in $CALADAN_PATCHES_DIR/*; do
  git am $patch
done

# Install Caladan
make submodules
(cd ksched && make -j `nproc`)
