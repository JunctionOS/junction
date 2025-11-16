set -xe

# Globals
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
ROOT_DIR=${SCRIPT_DIR}/..
CODE_DIR=${ROOT_DIR}/junction
FORMAT_PATH=${ROOT_DIR}/.clang-format

# check format for C++
# style is based on Google's style, defined in the .clang-format file
find "${CODE_DIR}" -iname '*.h' -o -iname '*.cc' | xargs clang-format-20 -style=file:"${FORMAT_PATH}" --dry-run -Werror

# fmt Python
#yapf3 --style pep8 -i scripts/benchmark.py

wait
