#!/bin/bash

set +x

CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan
GLIBC_PATCHES_DIR=${ROOT_DIR}/lib/patches/glibc

RED='\033[0;31m'
NC='\033[0m' # No Color

prev=$(cat "$ROOT_DIR/lib/.caladan_installed_ver" 2>&1 || true)
cur=$(cat "$CALADAN_PATCHES_DIR"/* | sha256sum)

err=0

if [ "$prev" != "$cur" ]; then
	echo -n -e "$RED"
	echo "Patches for Caladan have been updated since last install"
	echo "Please run scripts/install_caladan.sh to update"
	echo -e "$NC"
	err=1
fi

prev=$(cat "$ROOT_DIR/lib/.glibc_installed_ver" 2>&1 || true)
cur=$(cat "$GLIBC_PATCHES_DIR"/* | sha256sum)

if [ "$prev" != "$cur" ]; then
	echo -n -e "$RED"
	echo "Patches for glibc have been updated since last install"
	echo "Please run scripts/install_glibc.sh to update"
	echo -e "$NC"
	err=1
fi

if [ "$err" = "1" ]; then
	exit 1
fi

set -x
