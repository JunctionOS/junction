#!/bin/bash
set -xe

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../../
FLAMEGRAPH_DIR=${ROOT_DIR}/lib/FlameGraph

OUTPUT_DIR="perf_$(date '+%Y-%m-%d_%H-%M-%S')"
mkdir ${OUTPUT_DIR}

# Record
sudo perf record -F 1000 --buildid-mmap --call-graph dwarf -o ${OUTPUT_DIR}/perf.data ${1+"$@"}
sudo chmod 777 ${OUTPUT_DIR}/perf.data

# Generate flamegraph
sudo perf script -i ${OUTPUT_DIR}/perf.data > ${OUTPUT_DIR}/perf.script
perl ${FLAMEGRAPH_DIR}/stackcollapse-perf.pl ${OUTPUT_DIR}/perf.script > ${OUTPUT_DIR}/flamegraph.folded
perl ${FLAMEGRAPH_DIR}/flamegraph.pl ${OUTPUT_DIR}/flamegraph.folded > ${OUTPUT_DIR}/flamegraph.svg

echo "Output stored in: ${OUTPUT_DIR}"
