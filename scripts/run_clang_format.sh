#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../

# List of directories to run clang-format on
DIRECTORIES="src inc test bindings"

# Run clang-format
for dir in $DIRECTORIES; do
  find "${ROOT_DIR}/${dir}" -regex '.*\.\(cpp\|hpp\|cc\|cxx|h\)' -exec clang-format -style=Google -i {} \;
done

