#!/bin/bash

set -e
set -x

SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
VENV_DIR=${ROOT_DIR}/bin/venv

sudo -E apt install -y libgl1 python3-venv
python3 -m venv ${VENV_DIR}
${VENV_DIR}/bin/pip install chameleon pillow numpy pyaes six torch opencv-python scikit-learn pandas tensorflow #[and-cuda]

pushd ${ROOT_DIR}/bin/
npm install sharp
popd
