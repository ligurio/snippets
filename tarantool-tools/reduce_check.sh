#!/bin/bash

/home/sergeyb/sources/MRG/tarantool/third_party/luajit/src/luajit 301-basic.lua >/dev/null 2>&1 | grep "fs_fixup_ret: Assertion"
ls -s 301-basic.lua

if [ $? != 0 ]; then
 exit 0
else
 exit 1
fi
