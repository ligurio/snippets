#!/usr/bin/env bash

function assert_equal {
    local arg1=$1
    local arg2=$2
    local comment=$3

    if [[ "X$arg1" != "X$arg2" ]]; then
        echo -n "not ok - $1 != $2 "
        echo `caller 0 | awk '{print $2}'` "#" $comment
    else
        echo -n "ok - "
        echo `caller 0 | awk '{print $2}'` "#" $comment
    fi
}

function test_func1 {
    assert_equal "A" "A" "A letter"
}

function test_func2 {
    assert_equal "B" "B" "B letter"
}

function test_func3 {
    assert_equal "C" "C" "C letter"
}

test_func1
test_func2
test_func3
