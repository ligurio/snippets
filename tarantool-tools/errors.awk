BEGIN {
    total = 0
    unmatched = 0
    for (i = 1; i <= NF; i++)
        err_num[$i] = 0
    err_pat[0] = "attempt to index"
    err_pat[1] = "attempt to call"
    err_pat[2] = "no loop to break"
    err_pat[3] = "attempt to perform arithmetic on"
    err_pat[4] = "attempt to compare"
    err_pat[5] = "attempt to concatenate"
    err_pat[6] = "initial value must be"
    err_pat[7] = "unexpected symbol near"
    err_pat[8] = "ambiguous syntax"
    err_pat[9] = "bad argument"
    err_pat[10] = "'end' expected"
    err_pat[11] = "'for' limit must be a"
    err_pat[12] = "'for' step must be a"
    err_pat[13] = "attempt to get length of"
    err_pat[14] = "table index is"
    err_pat[15] = "cannot use '...' outside a vararg function near '...'"
    err_pat[16] = "'<name>' expected near"
    err_pat[17] = "'then' expected near '='"
}

!/^luaL_loadbuffer|^lua_pcall/ { next }

{
    ++total
    err_matched = 0
    for (key in err_pat) {
        if ($0 ~ err_pat[key]) {
            ++err_num[key]
            err_matched = 1
        }
    }
    if (err_matched == 0) {
        print "NOT MATCHED: " $0
        ++unmatched
    }
}

END {
    printf "SUMMARY:\n"
    printf "Total number of errors: %d\n", total
    printf "Total number of unmatched errors: %d\n", unmatched
    for (key in err_pat) {
        printf "Error message: '%1.25s' %d\n", err_pat[key], err_num[key]
    }
}
