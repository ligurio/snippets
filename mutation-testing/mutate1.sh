#!/bin/bash

set -e

coverage="coverage.xml"
mutant_dir="mutant_dir"
cov_file="coverfile"

make_coverfile() {

   local source_path=$1
   local coverage=$2
   local cov_path=$3

   echo "make coverfile: $cov_path"
   python mut_results/check_cov "$source_path" "$coverage" "$cov_path"
}

process_file() {

   local path=$1
   local test_cmd=$2

   local filename=$(basename $path)
   local name="${filename%.*}"

   echo "Path: $path"
   echo "Command line: $test_cmd"

   local backup="$path._"
   echo "backup source file: $path --> $backup"
   cp $path $backup
   make_coverfile $path $coverage $cov_file
   [ -e $mutant_dir ] || mkdir $mutant_dir
   echo "mutate $path --cmd \"cp MUTANT $path; python mut_results/check_status.py $test_cmd\" --mutantDir $mutant_dir --lines $cov_file"
   mutate $path --cmd "cp MUTANT $path; python mut_results/check_status.py '$test_cmd'" --mutantDir $mutant_dir --lines $cov_file
   echo "restore source file: $backup --> $path"
   cp $backup $path
   rm -f "$cov_file"
   echo "============================================="
}

process_file "../sources/libs/kos/coresrv/entity/entity_api.c"  "make knentitytests/qtest knentitytests_failed/qtest"
process_file "../sources/libs/kos/coresrv/sl/sl-static.c"       "make knsltests/qtest"
process_file "../sources/libs/kos/coresrv/sl/sl_api.c"          "make knsltests/qtest"
process_file "../sources/libs/kos/coresrv/task/task_api.c"      "make kntasktests/qtest kntasktests_failed/qtest"
process_file "../sources/libs/kos/coresrv/thread/thread_api.c"  "make knthreadtests/qtest"
process_file "../sources/libs/kos/coresrv/vlog/vlog_api.c"      "make knvlogtests/qtest"
process_file "../sources/libs/kos/coresrv/time/time_api.c"      "make kntimetests/qtest"