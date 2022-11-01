#!/usr/bin/env bash

# Note:
# This is not intended to be invoked manually; it will be invoked when 
# configuring using CMake. 

# This script creates scripts to facilitate running the executables of the runtime. 
# The generated script will be called:
#   run_<EXECUTABLE_NAME>
# There are two modes for using this script depending if we are using a custom 
# loader or not.

# For the custom loader, the usage of the script is as follows:
#   ./setup_runner_scripts.sh CUSTOM_LOADER EXEC_ENV EXEC_LOADER_PATH EXEC_LIBRARY_PATH BINARY_NAME
#   where EXEC_ENV: defines any environment variables required by the executable 
#                   in a format of VAR_NAME=VAR_VALUE
# 	  EXEC_LOADER_PATH: absolute path to the custom loader 
# 	  EXEC_LIBRARY_PATH: contains the configuration for the library load path in 
#                        the format "--library-path  <LD_LOAD_PATH>"
#	  BINARY_NAME: the name of the executable (without the path)

# For the regular loader, the usage of the script is as follows:
#   ./setup_runner_scripts.sh STANDARD_LOADER EXEC_ENV BINARY_NAME
#   where EXEC_ENV: defines any environment variables required by the executable 
#                   in a format of VAR_NAME=VAR_VALUE
#	  BINARY_NAME: the name of the executable (without the path)

# Requirements: 
#   The executable (BINARY_NAME) should be located in the root of the build 
#   directory (i.e., ./build/).

set -xe

MODE=$1

SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

custom_loader () {
  local EXEC_ENV="$1"
  local EXEC_LOADER_PATH="$2"
  local EXEC_LIBRARY_PATH="$3"
  local BINARY_NAME="$4"

  RUNNER_FILE="run_${BINARY_NAME}"
  BUILD_DIR="$ROOT_DIR/build"

  cd $BUILD_DIR
  LAUNCH_CMD_PREFIX="exec env \$ARG"
  echo "#!/bin/bash\nARG=\"${EXEC_ENV} ${EXEC_LOADER_PATH} ${EXEC_LIBRARY_PATH}\"\n${LAUNCH_CMD_PREFIX} ./$BINARY_NAME \${1+\"\$@\"}" > $RUNNER_FILE
  chmod +x $RUNNER_FILE
}

standard_loader () {
  local EXEC_ENV="$1"
  local BINARY_NAME="$2"

  RUNNER_FILE="run_${BINARY_NAME}"
  BUILD_DIR="$ROOT_DIR/build"
  cd $BUILD_DIR

  LAUNCH_CMD_PREFIX="exec env \$ARG"
  echo "#!/bin/bash\nARG=\"${EXEC_ENV}\"\n${LAUNCH_CMD_PREFIX} ./$BINARY_NAME \${1+\"\$@\"}" > $RUNNER_FILE
  chmod +x $RUNNER_FILE
}
case $MODE in
  "CUSTOM_LOADER")
    custom_loader "$2" "$3" "$4" "$5"
    ;;

  "STANDARD_LOADER")
    standard_loader "$2" "$3"
    ;;

  *)
    echo "Invalid mode type $MODE"
    exit  1
    ;;
esac
