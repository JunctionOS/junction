#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

. "${SCRIPT_DIR}"/helpers.sh

RUST_DIR="${ROOT_DIR}/install/rust"
RUSTUP_HOME="${RUST_DIR}/rustup"
CARGO_HOME="${RUST_DIR}/cargo"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-nightly}"

install_missing_packages curl ca-certificates

mkdir -p "${RUST_DIR}"

arch=$(uname -m)
case "${arch}" in
  x86_64)
    rustup_target="x86_64-unknown-linux-gnu"
    ;;
  *)
    echo "Unsupported architecture for rustup-init (x86_64 only): ${arch}" >&2
    exit 1
    ;;
esac

if [ ! -x "${CARGO_HOME}/bin/rustup" ]; then
  rustup_init="${RUST_DIR}/rustup-init"
  if [ ! -x "${rustup_init}" ]; then
    curl -fsSL "https://static.rust-lang.org/rustup/dist/${rustup_target}/rustup-init" -o "${rustup_init}"
    chmod +x "${rustup_init}"
  fi

  RUSTUP_HOME="${RUSTUP_HOME}" \
    CARGO_HOME="${CARGO_HOME}" \
    "${rustup_init}" -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"
fi

RUSTUP_HOME="${RUSTUP_HOME}" \
  CARGO_HOME="${CARGO_HOME}" \
  "${CARGO_HOME}/bin/rustup" toolchain install "${RUST_TOOLCHAIN}"

RUSTUP_HOME="${RUSTUP_HOME}" \
  CARGO_HOME="${CARGO_HOME}" \
  "${CARGO_HOME}/bin/rustup" default "${RUST_TOOLCHAIN}"

"${CARGO_HOME}/bin/rustc" --version
