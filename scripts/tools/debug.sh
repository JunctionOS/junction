#!/bin/bash

# Note:
# This script is taken from glibc/build and slightly modified to suit our needs.

# Globals
SCRIPT_DIR=$(dirname $(readlink -f $0))
ROOT_DIR=${SCRIPT_DIR}/../../
BUILD_DIR=${ROOT_DIR}/build
GLIBC_BUILD_DIR=${ROOT_DIR}/lib/glibc/build
GLIBC_SOURCE_DIR=${ROOT_DIR}/lib/glibc
GLIBC_CMD_FILE=${GLIBC_BUILD_DIR}/debugglibc.gdb

CONTAINER=false
DIRECT=true
STATIC=false
SYMBOLSFILE=true
unset TESTCASE
unset BREAKPOINTS
unset ENVVARS

usage()
{
cat << EOF
Usage: $0 [OPTIONS] <program>

   Or: $0 [OPTIONS] -- <program> [<args>]...

  where <program> is the path to the program being tested,
  and <args> are the arguments to be passed to it.

Options:

  -h, --help
	Prints this message and leaves.

  The following options require one argument:

  -b, --breakpoint
	Breakpoints to set at the beginning of the execution
	(each breakpoint demands its own -b option, e.g. -b foo -b bar)
  -e, --environment-variable
	Environment variables to be set with 'exec-wrapper env' in GDB
	(each environment variable demands its own -e option, e.g.
	-e FOO=foo -e BAR=bar)

  The following options do not take arguments:

  -c, --in-container
	Run the test case inside a container and automatically attach
	GDB to it.
  -i, --no-direct
	Selects whether to pass the --direct flag to the program.
	--direct is useful when debugging glibc test cases. It inhibits the
	tests from forking and executing in a subprocess.
	Default behaviour is to pass the --direct flag, except when the
	program is run with user specified arguments using the "--" separator.
  -s, --no-symbols-file
	Do not tell GDB to load debug symbols from the program.
EOF
}

# Parse input options
while [[ $# > 0 ]]
do
  key="$1"
  case $key in
    -h|--help)
      usage
      exit 0
      ;;
    -b|--breakpoint)
      BREAKPOINTS="break $2\n$BREAKPOINTS"
      shift
      ;;
    -e|--environment-variable)
      ENVVARS="$2 $ENVVARS"
      shift
      ;;
    -c|--in-container)
      CONTAINER=true
      ;;
    -i|--no-direct)
      DIRECT=false
      ;;
    -s|--no-symbols-file)
      SYMBOLSFILE=false
      ;;
    --)
      shift
      TESTCASE=$1
      COMMANDLINE="$@"
      # Don't add --direct when user specifies program arguments
      DIRECT=false
      break
      ;;
    *)
      TESTCASE=$1
      COMMANDLINE=$TESTCASE
      ;;
  esac
  shift
done

# Check for required argument
if [ ! -v TESTCASE ]
then
  usage
  exit 1
fi

echo "TEST CASE $TESTCASE"

# Container tests needing locale data should install them in-container.
# Other tests/binaries need to use locale data from the build tree.
if [ "$CONTAINER" = false ]
then
  ENVVARS="GCONV_PATH=${GLIBC_BUILD_DIR}/iconvdata $ENVVARS"
  ENVVARS="LOCPATH=${GLIBC_BUILD_DIR}/localedata $ENVVARS"
  ENVVARS="LC_ALL=C $ENVVARS"
fi

# Expand environment setup command
if [ -v ENVVARS ]
then
  ENVVARSCMD="set exec-wrapper env $ENVVARS"
fi

# Expand direct argument
if [ "$DIRECT" == true ]
then
  DIRECT="--direct"
else
  DIRECT=""
fi

# Check if the test case is static
if file ${TESTCASE} | grep "statically linked" >/dev/null
then
  STATIC=true
else
  STATIC=false
fi

# Expand symbols loading command
if [ "$SYMBOLSFILE" == true ]
then
  SYMBOLSFILE="add-symbol-file ${TESTCASE}"
else
  SYMBOLSFILE=""
fi

# GDB commands template
template ()
{
cat <<EOF
set stop-on-solib-events 1
set environment C -E -x c-header
set auto-load safe-path ${GLIBC_BUILD_DIR}/nptl_db:\$debugdir:\$datadir/auto-load
set libthread-db-search-path ${GLIBC_BUILD_DIR}/nptl_db
__ENVVARS__
__SYMBOLSFILE__
break _dl_start_user
run --library-path ."${BUILD_DIR}":"${BUILD_DIR}"/src:"${GLIBC_BUILD_DIR}":"${GLIBC_BUILD_DIR}"/elf:"${GLIBC_BUILD_DIR}"/dlfcn:"${GLIBC_BUILD_DIR}"/nss:"${GLIBC_BUILD_DIR}"/nis:"${GLIBC_BUILD_DIR}"/rt:"${GLIBC_BUILD_DIR}"/resolv:"${GLIBC_BUILD_DIR}"/mathvec:"${GLIBC_BUILD_DIR}"/support:"${GLIBC_BUILD_DIR}"/crypt:"${GLIBC_BUILD_DIR}"/nptl:/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/lib64:"${BUILD_DIR}":"${BUILD_DIR}"/src:${GLIBC_BUILD_DIR}/nptl_db __COMMANDLINE__ __DIRECT__
__BREAKPOINTS__
EOF
}

# Generate the commands file for gdb initialization
template | sed -e "s|__ENVVARS__|$ENVVARSCMD|" -e "s|__SYMBOLSFILE__|$SYMBOLSFILE|" -e "s|__COMMANDLINE__|$COMMANDLINE|" -e "s|__DIRECT__|$DIRECT|" -e "s|__BREAKPOINTS__|$BREAKPOINTS|" > $GLIBC_CMD_FILE

echo
echo "Debugging glibc..."
echo "Build directory  : $GLIBC_BUILD_DIR"
echo "Source directory : $GLIBC_SOURCE_DIR"
echo "GLIBC Testcase   : $TESTCASE"
echo "GDB Commands     : $GLIBC_CMD_FILE"
echo "Env vars         : $ENVVARS"
echo

if [ "$CONTAINER" == true ]
then
# Use testrun.sh to start the test case with WAIT_FOR_DEBUGGER=1, then
# automatically attach GDB to it.
WAIT_FOR_DEBUGGER=1 ${GLIBC_BUILD_DIR}/testrun.sh --tool=container ${TESTCASE} &
gdb -x ${TESTCASE}.gdb
elif [ "$STATIC" == true ]
then
gdb ${TESTCASE}
else
# Start the test case debugging in two steps:
#   1. the following command invokes gdb to run the loader;
#   2. the commands file tells the loader to run the test case.
gdb -q -x ${GLIBC_CMD_FILE} -d ${GLIBC_SOURCE_DIR} ${GLIBC_BUILD_DIR}/elf/ld.so
fi