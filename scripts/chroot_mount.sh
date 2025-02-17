#!/bin/bash

set -e

SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=$(realpath ${SCRIPT_DIR}/../)
CHROOT_DIR=${ROOT_DIR}/chroot

MOUNT_POINTS=("${ROOT_DIR}/build" "${ROOT_DIR}/build-debug" "${ROOT_DIR}/install" "${ROOT_DIR}/bin")

mount_bind() {
  for mnt in "${MOUNT_POINTS[@]}"; do
    if [ ! -d "$mnt" ]; then
      echo "Skipping $mnt: Directory does not exist."
      continue
    fi
    if ! mountpoint -q "$CHROOT_DIR/$mnt"; then
      echo "Mounting $mnt..."
      sudo mkdir -p "$CHROOT_DIR/$mnt"
      sudo mount --bind "/$mnt" "$CHROOT_DIR/$mnt"
    else
      echo "$mnt is already mounted."
    fi
  done
}

unmount_bind() {
  for mnt in "${MOUNT_POINTS[@]}"; do
    while mountpoint -q "$CHROOT_DIR/$mnt"; do
      echo "Unmounting $mnt..."
      sudo umount "$CHROOT_DIR/$mnt"
    done
  done
}

if [[ $1 == "-u" ]]; then
  unmount_bind
else
  mount_bind
fi
