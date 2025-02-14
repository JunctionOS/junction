#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
BIN_DIR=${ROOT_DIR}/bin

mkdir -p $BIN_DIR
cd $BIN_DIR

CMAKE_VER=3.31.5

EXPECTED_SHA="79ef8d796c0dc16f75b9fb63ddc3fd4191c641db3cd08cb08bafd9e993797596"
FILE="$BIN_DIR/bin/cmake"

# Install a specific version of cmake
if [ ! -f "$FILE" ] || [ "$(shasum -a 256 "$FILE" | awk '{print $1}')" != "$EXPECTED_SHA" ]; then
  wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}-linux-x86_64.sh
  chmod +x cmake-${CMAKE_VER}-linux-x86_64.sh
  ./cmake-${CMAKE_VER}-linux-x86_64.sh --skip-license
  rm cmake-${CMAKE_VER}-linux-x86_64.sh
fi
