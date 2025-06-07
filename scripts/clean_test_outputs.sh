#!/bin/bash

# Exit on any error
set -e

# Check if REM_FILES is set
if [[ -n "$REM_FILES" ]]; then
  echo "REM_FILES is set — skipping cleanup."
  exit 0
fi

# Cleanup paths passed as arguments
echo "Cleaning up: $@"
for f in "$@"; do
  rm -f $CHROOT_DIR/$f
done
