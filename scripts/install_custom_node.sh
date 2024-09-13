#!/bin/bash

set -e
set -x

SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

if [ ! -d "${ROOT_DIR}/lib/node" ]; then
  git clone -b gc-freeze https://github.com/joshuafried/node ${ROOT_DIR}/lib/node
fi

cd ${ROOT_DIR}/lib/node
./configure --prefix=${ROOT_DIR}/install --without-npm --without-corepack --shared --shared-zlib --shared-cares --shared-nghttp2 --shared-brotli --shared-builtin-undici/undici-path=/usr/share/nodejs/undici/undici-fetch.js --shared-builtin-acorn-path=/usr/share/nodejs/acorn/dist/acorn.js --shared-builtin-acorn_walk-path=/usr/share/nodejs/acorn-walk/dist/walk.js --shared-builtin-cjs_module_lexer/lexer-path=/usr/share/nodejs/cjs-module-lexer/lexer.js --shared-builtin-cjs_module_lexer/dist/lexer-path=/usr/share/nodejs/cjs-module-lexer/dist/lexer.js --with-intl=system-icu --shared-openssl --openssl-use-def-ca-store --arch-triplet=x86_64-linux-gnu --node-relative-path="lib/x86_64-linux-gnu/nodejs:share/nodejs" --shared-libuv --dest-os=linux --dest-cpu=x64

make -j `nproc`
make -j `nproc` install

cd ${ROOT_DIR}/bin
npm install node-gyp

cd ${ROOT_DIR}/junction/samples/snapshots/node/addon
node-gyp configure build --nodedir=${ROOT_DIR}/install
mkdir -p ${ROOT_DIR}/bin/node_modules_addon
cp build/Release/addon.node ${ROOT_DIR}/bin/node_modules_addon
