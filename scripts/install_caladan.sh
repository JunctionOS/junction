#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CALADAN_DIR=${ROOT_DIR}/lib/caladan
CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan

# Install Linux packages
sudo -E apt install -y make cmake pkg-config libnl-3-dev libnl-route-3-dev libnuma-dev uuid-dev libssl-dev libaio-dev libcunit1-dev libclang-dev libncurses-dev meson python3-pyelftools

cd $CALADAN_DIR/../
git submodule update --init --recursive -f caladan

# Apply patches
cd $CALADAN_DIR/
git -c user.name="x" -c user.email="x" am $CALADAN_PATCHES_DIR/*

prev=$(cat "$ROOT_DIR/lib/.caladan_installed_ver" 2>&1 || true)
cur=$(cat "$CALADAN_PATCHES_DIR"/* | sha256sum)

# Install Caladan
if [ "$prev" != "$cur" ] || [ ! -f $CALADAN_DIR/deps/pcm/build/src/libpcm.a ]; then
  make submodules
fi

(cd ksched && make -j `nproc`)

cat $CALADAN_PATCHES_DIR/* | sha256sum >  $CALADAN_DIR/../.caladan_installed_ver
