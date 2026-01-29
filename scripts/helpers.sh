#!/bin/bash

# install_missing_packages: Given a list of package names, installs only those
# not currently installed (as determined by `dpkg -s`). Performs a single
# `apt-get install -y` call if there are any missing packages.
install_missing_packages() {
  set +x
  local pkgs=("$@")
  local missing=()

  local pkg
  for pkg in "${pkgs[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    sudo apt update || true
    sudo -E DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  fi
  set -x
}