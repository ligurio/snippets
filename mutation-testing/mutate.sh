#!/bin/bash

set -e

# sources/libs/kos/coresrv/entity/entity_api.c  make knentitytests/qtest
# sources/libs/kos/coresrv/sl/sl-static.c       make knsltests/qtest
# sources/libs/kos/coresrv/sl/sl_api.c          make knsltests/qtest
# sources/libs/kos/coresrv/task/task_api.c      make kntasktests/qtest
# sources/libs/kos/coresrv/thread/thread_api.c  make knthreadtests/qtest
# sources/libs/kos/coresrv/time/time_api.c      make kntimetests/qtest
# sources/libs/kos/coresrv/vlog/vlog_api.c      make knvlogtests/qtest

prepare() {

   local mutant=$1
   local path=$2

   echo "copy $mutant to $path"
   cp $mutant $path
}

runtest() {

   local path=$1
   local test_cmd=$2

   echo "run tests"
   echo "$test_cmd"
   python check_status.py "$test_cmd" && echo "SURVIVED ($path)" || true
}

process_file() {

   local path=$1
   local test_cmd=$2

   local filename=$(basename $path)
   local name="${filename%.*}"
   local pattern="$name.mutant.*.c"

   echo "Path: $1"
   echo "Command line: $2"
   echo "Pattern: $pattern"

   local mutated_sources=$(find $name -name "$pattern" -print)
   local backup="$path._"

   echo "backup source file: $path --> $backup"
   cp $path $backup
   for m in $mutated_sources; do
       echo "current mutant: $m"
       prepare $m $path
       runtest $m "$test_cmd"
       diff -u $path $m || true
   done
   echo "restore source file: $backup --> $path"
   cp $backup $path
   echo "============================================="
}

process_file "../sources/libs/kos/coresrv/entity/entity_api.c"  "make knentitytests/qtest"
process_file "../sources/libs/kos/coresrv/sl/sl-static.c"       "make knsltests/qtest"
process_file "../sources/libs/kos/coresrv/sl/sl_api.c"          "make knsltests/qtest"
process_file "../sources/libs/kos/coresrv/task/task_api.c"      "make kntasktests/qtest"
process_file "../sources/libs/kos/coresrv/thread/thread_api.c"  "make knthreadtests/qtest"
process_file "../sources/libs/kos/coresrv/vlog/vlog_api.c"      "make knvlogtests/qtest"
#process_file "../sources/libs/kos/coresrv/time/time_api.c"     "make kntimetests/qtest"