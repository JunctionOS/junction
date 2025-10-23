#!/bin/bash
set -xe

# Get flags
CI_MODE=false
if [ "$1" == "--ci" ]; then
    CI_MODE=true
    echo "Running in CI mode: Makefile will be patched."
fi

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CALADAN_DIR=${ROOT_DIR}/lib/caladan
if [ "$CI_MODE" = true ]; then
    CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan-ci
else
    CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan
fi

# Install Linux packages
sudo -E apt install -y make cmake pkg-config libnl-3-dev libnl-route-3-dev libnuma-dev uuid-dev libssl-dev libaio-dev libcunit1-dev libclang-dev libncurses-dev meson python3-pyelftools

cd $CALADAN_DIR/../
git submodule update --init --recursive -f caladan

# Switch to dev branch in CI_MODE
if [ "$CI_MODE" = true ]; then
    echo "Switching Caladan submodule to dev branch."
    cd $CALADAN_DIR
    git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
    git fetch origin dev
    git branch -a
    git checkout dev
fi

# Apply patches
cd $CALADAN_DIR/
if [ "$CI_MODE" = true ]; then
    echo "Applying patches with 'git apply' for CI..."
    git apply --reject --whitespace=fix $CALADAN_PATCHES_DIR/* || true

    echo "--- Checking for failed patch rejects (.rej files) ---"
    REJECT_FILES=$(find . -name "*.rej")
    if [ -n "$REJECT_FILES" ]; then
        echo "Patch application failed. Displaying reject file contents:"
        for file in $REJECT_FILES; do
            echo "--- Contents of $file ---"
            cat "$file"
            echo "--------------------------"
        done
        exit 1
    else
        echo "Path applied successfully."
    fi
else
    git -c user.name="x" -c user.email="x" am $CALADAN_PATCHES_DIR/*
fi

prev=$(cat "$ROOT_DIR/lib/.caladan_installed_ver" 2>&1 || true)
cur=$(cat "$CALADAN_PATCHES_DIR"/* | sha256sum)

# Install Caladan
if [ "$prev" != "$cur" ] || [ ! -f $CALADAN_DIR/deps/pcm/build/src/libpcm.a ]; then
  make submodules
fi

(cd ksched && make -j `nproc`)

cat $CALADAN_PATCHES_DIR/* | sha256sum >  $CALADAN_DIR/../.caladan_installed_ver
