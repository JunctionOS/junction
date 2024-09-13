#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
GLIBC_DIR=${ROOT_DIR}/lib/glibc
GLIBC_PATCHES_DIR=${ROOT_DIR}/lib/patches/glibc
GLIBC_INSTALL_DIR=${ROOT_DIR}/install

# Create installation directory
mkdir -p $GLIBC_INSTALL_DIR

prev=$(cat "$ROOT_DIR/lib/.glibc_installed_ver" 2>&1 || true)
cur=$(cat "$GLIBC_PATCHES_DIR"/* | sha256sum)

if [ "$prev" == "$cur" ] && [ -f $GLIBC_INSTALL_DIR/lib/ld-linux-x86-64.so.2 ] && [ -f $GLIBC_INSTALL_DIR/lib/libc.so.6 ]; then
  exit 0
fi

unset LD_LIBRARY_PATH

cd $GLIBC_DIR/../
git submodule update --init --recursive -f glibc

# Apply patches
cd $GLIBC_DIR
git -c user.name="x" -c user.email="x" am $GLIBC_PATCHES_DIR/*

# Build and install glibc
mkdir -p build
cd build
../configure --prefix $GLIBC_INSTALL_DIR
make -j "$(nproc)" CFLAGS="-U_FORTIFY_SOURCE -O3"

##
## glibc may emit two sets of indirect call instructions for calling into Junction.
## One is of the form "mov 0x200e28,%rax; call %rax", the other "call   *0x200e28".
## Both are safe, but the former produces problems when snapshotting with ASLR enabled.
## Check the binary for the former and reject the build if it uses it.
##

(objdump -S  ${GLIBC_DIR}/build/libc.so.6 |& grep -e 0x200e20 -e 0x200e28 -e 0x200e30 | grep -q -v call) && (echo -e "\033[0;31m Bad instruction sequence in libc binary \033[0m"; exit -1)

make install -j "$(nproc)"

# record the set of patches used for this build
cat $GLIBC_PATCHES_DIR/* | sha256sum >  $GLIBC_DIR/../.glibc_installed_ver
