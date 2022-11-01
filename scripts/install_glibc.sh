#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
GLIBC_DIR=${ROOT_DIR}/lib/glibc
GLIBC_PATCHES_DIR=${ROOT_DIR}/lib/patches/glibc
GLIBC_INSTALL_DIR=${ROOT_DIR}/bin/glibc/build/install

# Create installation directory
mkdir -p $GLIBC_INSTALL_DIR

unset LD_LIBRARY_PATH


# Apply patches
cd $GLIBC_DIR
for patch in $GLIBC_PATCHES_DIR/*; do
  git am $patch
done

# Build and install glibc
mkdir -p build
cd build
../configure --prefix $GLIBC_INSTALL_DIR
make -j "$(nproc)"
make install -j "$(nproc)"
