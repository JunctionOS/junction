#!/bin/bash

# Note:
# This script is taken from glibc/build and slightly modified to suit our needs.

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../../
BUILD_DIR=${ROOT_DIR}/build
GLIBC_BUILD_DIR=${ROOT_DIR}/lib/glibc/build
GCONV_PATH=${GLIBC_BUILD_DIR}/iconvdata

usage () {
cat << EOF
Usage: $0 [OPTIONS] <program> [ARGUMENTS...]

  --tool=TOOL  Run with the specified TOOL. It can be strace, rpctrace,
               valgrind or container. The container will run within
               support/test-container.
EOF

  exit 1
}

toolname=default
while test $# -gt 0 ; do
  case "$1" in
    --tool=*)
      toolname="${1:7}"
      shift
      ;;
    --*)
      usage
      ;;
    *)
      break
      ;;
  esac
done

if test $# -eq 0 ; then
  usage
fi

case "$toolname" in
  default)
    exec env GCONV_PATH="${GLIBC_BUILD_DIR}"/iconvdata LOCPATH="${GLIBC_BUILD_DIR}"/localedata LC_ALL=C "${GLIBC_BUILD_DIR}"/elf/ld-linux-x86-64.so.2 --library-path .:"${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl:"${ROOT_DIR}"/lib/python/3.10.0/lib:/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/lib64:"${BUILD_DIR}":"${BUILD_DIR}"/src ${1+"$@"}
    ;;
  strace)
    exec strace  -EGCONV_PATH="${GLIBC_BUILD_DIR}"/iconvdata  -ELOCPATH="${GLIBC_BUILD_DIR}"/localedata  -ELC_ALL=C  "${GLIBC_BUILD_DIR}"/elf/ld-linux-x86-64.so.2 --library-path "${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/math:"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl ${1+"$@"}
    ;;
  rpctrace)
    exec rpctrace  -EGCONV_PATH="${GLIBC_BUILD_DIR}"/iconvdata  -ELOCPATH="${GLIBC_BUILD_DIR}"/localedata  -ELC_ALL=C  "${GLIBC_BUILD_DIR}"/elf/ld-linux-x86-64.so.2 --library-path "${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/math:"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl ${1+"$@"}
    ;;
  valgrind)
    exec env GCONV_PATH="${GLIBC_BUILD_DIR}"/iconvdata LOCPATH="${GLIBC_BUILD_DIR}"/localedata LC_ALL=C valgrind  "${GLIBC_BUILD_DIR}"/elf/ld-linux-x86-64.so.2 --library-path "${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/math:"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl ${1+"$@"}
    ;;
  container)
    exec env GCONV_PATH="${GLIBC_BUILD_DIR}"/iconvdata LOCPATH="${GLIBC_BUILD_DIR}"/localedata LC_ALL=C  "${GLIBC_BUILD_DIR}"/elf/ld-linux-x86-64.so.2 --library-path "${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/math:"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl "${GLIBC_BUILD_DIR}"/support/test-container env GCONV_PATH="${GLIBC_BUILD_DIR}"/iconvdata LOCPATH="${GLIBC_BUILD_DIR}"/localedata LC_ALL=C  "${GLIBC_BUILD_DIR}"/elf/ld-linux-x86-64.so.2 --library-path "${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/math:"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl ${1+"$@"}
    ;;
  *)
    usage
    ;;
esac