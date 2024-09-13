#!/bin/bash

set -ex

SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../
CHROOT=${ROOT_DIR}/chroot

if ! mkdir ${CHROOT}; then
 echo "chroot already exists. please remove the directory and run again"
 exit 0
fi

export DEBIAN_FRONTEND=noninteractive

sudo apt update
sudo -E apt install -y debootstrap

sudo debootstrap --arch=amd64 noble ${CHROOT}  http://archive.ubuntu.com/ubuntu/

sudo mount -o ro --bind /proc ${CHROOT}/proc
sudo chroot ${CHROOT} /bin/bash <<"EOT"
echo deb http://archive.ubuntu.com/ubuntu noble universe >> /etc/apt/sources.list
apt update
apt install -y nodejs libgl1 gfortran ruby php-cli python3-pil openjdk-21-jre-headless
EOT

sudo umount ${CHROOT}/proc

sudo cp ${ROOT_DIR}/install/sbin/ldconfig ${CHROOT}/sbin/
