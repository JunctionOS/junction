#!/bin/bash

set -e
set -x

SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
VENV_DIR=${ROOT_DIR}/bin/venv

sudo -E apt install -y libgl1 python3-venv python3-grpcio python3-grpc-tools
mkdir -p ${ROOT_DIR}/bin/
python3 -m venv ${VENV_DIR}
${VENV_DIR}/bin/pip install chameleon pillow numpy pyaes six torch opencv-python scikit-learn pandas tensorflow grpcio grpcio-tools minio #[and-cuda]
${VENV_DIR}/bin/pip install matplotlib psutil

pushd ${ROOT_DIR}/bin/
npm install sharp
popd

pushd ${ROOT_DIR}/bin/bin
if [ ! -f "minio" ]; then
  wget -O minio.download https://dl.min.io/server/minio/release/linux-amd64/minio
  mv minio.download minio
fi
popd
