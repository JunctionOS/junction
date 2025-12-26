#!/bin/bash

set +x

CI_MODE=false
if [ "$1" == "--ci" ]; 
then
    CI_MODE=true
    echo "INFO: sumodule check running in CI mode."
fi

if [ "$CI_MODE" = true ]; then
    CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan-ci
else
    CALADAN_PATCHES_DIR=${ROOT_DIR}/lib/patches/caladan
fi
GLIBC_PATCHES_DIR=${ROOT_DIR}/lib/patches/glibc

RED='\033[0;31m'
NC='\033[0m' # No Color

if [ ! -f ${ROOT_DIR}/.install_script_ran ]; then
	echo -n -e "$RED"
	echo "Please run scripts/install.sh first."
	echo -e "$NC"
	exit 1
fi

prev=$(cat "$ROOT_DIR/lib/.caladan_installed_ver" 2>&1 || true)
cur=$((cd ${ROOT_DIR}; git ls-tree HEAD lib/caladan; cat "$CALADAN_PATCHES_DIR"/*) | sha256sum)


err=0

if [ "$prev" != "$cur" ]; then
	echo -n -e "$RED"
	echo "Patches for Caladan have been updated since last install"
	echo "Please run scripts/install_caladan.sh to update"
	echo -e "$NC"
	err=1
	echo prev $prev
	echo cur $cur
fi

prev=$(cat "$ROOT_DIR/lib/.glibc_installed_ver" 2>&1 || true)
cur=$((git ls-tree HEAD ${ROOT_DIR}/lib/glibc; cat "$GLIBC_PATCHES_DIR"/*) | sha256sum)

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
