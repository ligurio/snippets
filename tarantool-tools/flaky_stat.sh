#!/bin/sh

# https://github.com/tarantool/tarantool/issues/4974

tests="box/hash_64bit_delete.test.lua
box/tree_pk.test.lua
box/protocol.test.lua
box/schema_reload.test.lua
box/leak.test.lua
box/func_reload.test.lua
box/stat_net.test.lua
box/admin.test.lua
box/on_shutdown.test.lua
box/iproto.test.lua
box/tree_pk_multipart.test.lua
box/gh-4593-netbox-on_connect-disconnect.test.lua
box/access_misc.test.lua
box/role.test.lua
box/gh-4770-broken-pairs-for-space-objects.test.lua
box/rtree_array.test.lua
box/space_bsize.test.lua
box/gh-4513-netbox-self-and-connect-interchangeable.test.lua
box/iproto_stress.test.lua
box/hash_string_select.test.lua
box/hash_with_function.test.lua
box/net.box.test.lua
box/access.test.lua
box/temp_spaces.test.lua
box/hash_replace.test.lua
box/misc.test.lua
box/hash_64bit_replace.test.lua
box/hash_string_insert.test.lua
box/hash_32bit_select.test.lua
box/hash_64bit_insert.test.lua
box/on_replace.test.lua
box/hash_64bit_select.test.lua
box/gh-4627-session-use-after-free.test.lua
box/rtree_misc.test.lua
box/net_msg_max.test.lua
box/access_sysview.test.lua
box/access_bin.test.lua
box/update.test.lua
box/error.test.lua
box/hash_string_replace.test.lua
box/hash_collation.test.lua
box/alter_limits.test.lua
box/sql.test.lua
box/sequence.test.lua
box/backup.test.lua
box/function1.test.lua
box/errinj_index.test.lua
box/tuple_bench.test.lua
box/rtree_point_r2.test.lua
box/rtree_point.test.lua
box/sql-update-with-nested-select.test.lua
box/hash_32bit_delete.test.lua
box/upsert_errinj.test.lua
box/info.test.lua
box/transaction.test.lua
box/rtree_errinj.test.lua
box/gh-4672-min-integer-value-in-serializer.test.lua
box/call.test.lua
box/cfg.test.lua
box/ddl.test.lua
box/hash_32bit_replace.test.lua
box/hash_iterate.test.lua
box/hash_32bit_insert.test.lua
box/gh-4648-func-load-unload.test.lua
box/errinj.test.lua
box/hash_gh-3907.test.lua
box/hash_multipart.test.lua
box/iterator.test.lua
box/tuple.test.lua
box/hash_gh-1467.test.lua
box/bitset.test.lua
box/alter.test.lua
box/hash_gh-616.test.lua
box/gh-2763-session-credentials-update.test.lua
box/push.test.lua
box/before_replace.test.lua
box/reconfigure.test.lua
box/gh-4769-unprepare-response-body.test.lua
box/indices_any_type.test.lua
box/rtree_rect.test.lua
box/stat.test.lua
box/lua.test.lua
box/select.test.lua
box/blackhole.test.lua
box/hash_not_a_multikey.test.lua
box/varbinary_type.test.lua
box/gh-4511-access-settings-from-any-frontend.test.lua
box/access_escalation.test.lua
box/hash_string_delete.test.lua
app-tap/yaml.test.lua
app-tap/logger.test.lua
app-tap/gh-4761-json-per-call-options.test.lua
app-tap/clock.test.lua
app-tap/http_client.test.lua
app-tap/debug.test.lua
app-tap/console_lua.test.lua
app-tap/table.test.lua
app-tap/errno.test.lua
app-tap/inspector.test.lua
app-tap/iconv.test.lua
app-tap/snapshot.test.lua
app-tap/uri.test.lua
app-tap/console.test.lua
app-tap/msgpackffi.test.lua
app-tap/pcall.test.lua
app-tap/json.test.lua
app-tap/info.test.lua
app-tap/msgpack.test.lua
app-tap/cfg.test.lua
app-tap/minimal.test.lua
app-tap/pwd.test.lua
app-tap/trigger.test.lua
app-tap/csv.test.lua
app-tap/logger_pipe.test.lua
app-tap/func.test.lua
app-tap/string.test.lua
app-tap/init_script.test.lua
app-tap/module_api.test.lua
app-tap/fail_main.test.lua
app-tap/tarantoolctl.test.lua
app-tap/tap.test.lua
swim/swim.test.lua
swim/errinj.test.lua
vinyl/constraint.test.lua
vinyl/errinj_gc.test.lua
vinyl/large.test.lua
vinyl/replica_rejoin.test.lua
vinyl/dump_stress.test.lua
vinyl/deferred_delete.test.lua
vinyl/options.test.lua
vinyl/replica_quota.test.lua
vinyl/snapshot.test.lua
vinyl/write_iterator.test.lua
vinyl/tx_gap_lock.test.lua
vinyl/savepoint.test.lua
vinyl/recovery_quota.test.lua
vinyl/split_coalesce.test.lua
vinyl/tx_serial.test.lua
vinyl/quota.test.lua
vinyl/misc.test.lua
vinyl/errinj_stat.test.lua
vinyl/on_replace.test.lua
vinyl/snap_io_rate.test.lua
vinyl/upgrade.test.lua
vinyl/compact.test.lua
vinyl/errinj_vylog.test.lua
vinyl/json.test.lua
vinyl/quota_timeout.test.lua
vinyl/gc.test.lua
vinyl/partial_dump.test.lua
vinyl/upsert.test.lua
vinyl/ddl.test.lua
vinyl/errinj.test.lua
vinyl/parallel.test.lua
vinyl/stress.test.lua
vinyl/throttle.test.lua
vinyl/select_consistency.test.lua
vinyl/iterator.test.lua
vinyl/mvcc.test.lua
vinyl/layout.test.lua
vinyl/gh-4810-dump-during-index-build.test.lua
vinyl/update_optimize.test.lua
vinyl/cache.test.lua
vinyl/errinj_ddl.test.lua
vinyl/recover.test.lua
vinyl/stat.test.lua
vinyl/tx_conflict.test.lua
vinyl/bloom.test.lua
vinyl/hermitage.test.lua
vinyl/errinj_tx.test.lua
vinyl/gh.test.lua
vinyl/write_iterator_rand.test.lua
engine/replace.test.lua
engine/decimal.test.lua
engine/recover_drop.test.lua
engine/recover_snapshot_wal.test.lua
engine/insert.test.lua
engine/tree_variants.test.lua
engine/delete.test.lua
engine/replica_join.test.lua
engine/crossjoin.test.lua
engine/snapshot.test.lua
engine/savepoint.test.lua
engine/misc.test.lua
engine/truncate.test.lua
engine/update.test.lua
engine/json.test.lua
engine/null.test.lua
engine/upsert.test.lua
engine/recover_snapshot.test.lua
engine/params.test.lua
engine/transaction.test.lua
engine/tree.test.lua
engine/func_index.test.lua
engine/ddl.test.lua
engine/errinj.test.lua
engine/iterator.test.lua
engine/tuple.test.lua
engine/recover_wal.test.lua
engine/conflict.test.lua
engine/errinj_ddl.test.lua
engine/indices_any_type.test.lua
engine/lua.test.lua
engine/select.test.lua
engine/multikey.test.lua
engine/hints.test.lua
box-tap/feedback_daemon.test.lua
box-tap/on_schema_init.test.lua
box-tap/net.box.test.lua
box-tap/schema_mt.test.lua
box-tap/key_def.test.lua
box-tap/cfgup.test.lua
box-tap/gc.test.lua
box-tap/session.storage.test.lua
box-tap/trigger_atexit.test.lua
box-tap/cfg.test.lua
box-tap/session.test.lua
box-tap/auth.test.lua
box-tap/trigger_yield.test.lua
box-tap/merger.test.lua
xlog/gh-4771-upgrade.test.lua
xlog/checkpoint_threshold.test.lua
xlog/checkpoint_daemon.test.lua
xlog/panic_on_wal_error.test.lua
xlog/panic_on_broken_lsn.test.lua
xlog/gh1433.test.lua
xlog/reader.test.lua
xlog/misc.test.lua
xlog/snap_io_rate.test.lua
xlog/transaction.test.lua
xlog/errinj.test.lua
xlog/big_tx.test.lua
xlog/force_recovery.test.lua
xlog/header.test.lua
sql-tap/tkt-3998683a16.test.lua
sql-tap/tkt-4c86b126f2.test.lua
sql-tap/where6.test.lua
sql-tap/orderby6.test.lua
sql-tap/misc5.test.lua
sql-tap/tkt3935.test.lua
sql-tap/aggnested.test.lua
sql-tap/insert1.test.lua
sql-tap/orderby4.test.lua
sql-tap/whereI.test.lua
sql-tap/insert3.test.lua
sql-tap/gh2130-index-refer-table.test.lua
sql-tap/join2.test.lua
sql-tap/gh-2884-forbid-rowid-syntax.test.lua
sql-tap/selectA.test.lua
sql-tap/in1.test.lua
sql-tap/tkt-a8a0d2996a.test.lua
sql-tap/identifier_case.test.lua
sql-tap/position.test.lua
sql-tap/index1.test.lua
sql-tap/tkt3554.test.lua
sql-tap/atof1.test.lua
sql-tap/tkt-868145d012.test.lua
sql-tap/gh-2931-savepoints.test.lua
sql-tap/tkt2832.test.lua
sql-tap/tkt3442.test.lua
sql-tap/in4.test.lua
sql-tap/index4.test.lua
sql-tap/misc3.test.lua
sql-tap/trigger5.test.lua
sql-tap/in5.test.lua
sql-tap/join6.test.lua
sql-tap/tkt1537.test.lua
sql-tap/analyze6.test.lua
sql-tap/in3.test.lua
sql-tap/trigger1.test.lua
sql-tap/select2.test.lua
sql-tap/select9.test.lua
sql-tap/gh-2360-omit-truncate-in-transaction.test.lua
sql-tap/gh2548-select-compound-limit.test.lua
sql-tap/analyzeD.test.lua
sql-tap/where2.test.lua
sql-tap/like3.test.lua
sql-tap/orderby5.test.lua
sql-tap/trigger4.test.lua
sql-tap/tkt2822.test.lua
sql-tap/tkt-7bbfb7d442.test.lua
sql-tap/select4.test.lua
sql-tap/gh-2549-many-columns.test.lua
sql-tap/join.test.lua
sql-tap/fkey4.test.lua
sql-tap/select1.test.lua
sql-tap/tkt-31338dca7e.test.lua
sql-tap/triggerB.test.lua
sql-tap/index3.test.lua
sql-tap/tkt3731.test.lua
sql-tap/date.test.lua
sql-tap/tkt-b1d3a2e531.test.lua
sql-tap/tkt-02a8e81d44.test.lua
sql-tap/tkt3773.test.lua
sql-tap/tkt1444.test.lua
sql-tap/table.test.lua
sql-tap/join5.test.lua
sql-tap/tkt-91e2e8ba6f.test.lua
sql-tap/subquery.test.lua
sql-tap/cse.test.lua
sql-tap/tkt3201.test.lua
sql-tap/drop_all.test.lua
sql-tap/tkt-b75a9ca6b0.test.lua
sql-tap/select5.test.lua
sql-tap/tkt-f973c7ac31.test.lua
sql-tap/func5.test.lua
sql-tap/tkt-fa7bf5ec.test.lua
sql-tap/tkt3419.test.lua
sql-tap/tkt-ba7cbfaedc.test.lua
sql-tap/tkt3493.test.lua
sql-tap/select6.test.lua
sql-tap/selectE.test.lua
sql-tap/with2.test.lua
sql-tap/whereA.test.lua
sql-tap/whereB.test.lua
sql-tap/minmax2.test.lua
sql-tap/whereG.test.lua
sql-tap/boundary1.test.lua
sql-tap/analyzeF.test.lua
sql-tap/collation.test.lua
sql-tap/func3.test.lua
sql-tap/tkt-38cb5df375.test.lua
sql-tap/subquery2.test.lua
sql-tap/tkt1501.test.lua
sql-tap/blob.test.lua
sql-tap/boundary3.test.lua
sql-tap/tkt3541.test.lua
sql-tap/index-info.test.lua
sql-tap/autoindex4.test.lua
sql-tap/trigger8.test.lua
sql-tap/tkt-8c63ff0ec.test.lua
sql-tap/transitive1.test.lua
sql-tap/orderby1.test.lua
sql-tap/randexpr1.test.lua
sql-tap/hexlit.test.lua
sql-tap/subselect.test.lua
sql-tap/tkt1473.test.lua
sql-tap/update.test.lua
sql-tap/selectF.test.lua
sql-tap/gh-2723-concurrency.test.lua
sql-tap/tkt2942.test.lua
sql-tap/analyze5.test.lua
sql-tap/analyze1.test.lua
sql-tap/tkt-4dd95f6943.test.lua
sql-tap/gh-2996-indexed-by.test.lua
sql-tap/join4.test.lua
sql-tap/tokenize.test.lua
sql-tap/tkt3298.test.lua
sql-tap/analyze7.test.lua
sql-tap/debug_mode_only.test.lua
sql-tap/tkt2339.test.lua
sql-tap/index7.test.lua
sql-tap/alias.test.lua
sql-tap/tkt3879.test.lua
sql-tap/tkt3334.test.lua
sql-tap/triggerC.test.lua
sql-tap/lua_sql.test.lua
sql-tap/selectG.test.lua
sql-tap/between.test.lua
sql-tap/analyzeE.test.lua
sql-tap/start-transaction.test.lua
sql-tap/tkt-80e031a00f.test.lua
sql-tap/tkt3581.test.lua
sql-tap/e_delete.test.lua
sql-tap/tkt-a7b7803e.test.lua
sql-tap/types2.test.lua
sql-tap/trigger2.test.lua
sql-tap/select8.test.lua
sql-tap/whereC.test.lua
sql-tap/null.test.lua
sql-tap/tkt2640.test.lua
sql-tap/fkey2.test.lua
sql-tap/tkt3791.test.lua
sql-tap/tkt3508.test.lua
sql-tap/tkt-752e1646fc.test.lua
sql-tap/offset1.test.lua
sql-tap/trigger9.test.lua
sql-tap/analyze4.test.lua
sql-tap/badutf1.test.lua
sql-tap/bigrow1.test.lua
sql-tap/misc1.test.lua
sql-tap/boundary2.test.lua
sql-tap/tkt-b351d95f9.test.lua
sql-tap/resolver01.test.lua
sql-tap/fkey1.test.lua
sql-tap/analyze9.test.lua
sql-tap/tkt-4ef7e3cfca.test.lua
sql-tap/tkt1449.test.lua
sql-tap/tkt3522.test.lua
sql-tap/icu.test.lua
sql-tap/join3.test.lua
sql-tap/gh-3297-ephemeral-rowid.test.lua
sql-tap/whereK.test.lua
sql-tap/cast.test.lua
sql-tap/func2.test.lua
sql-tap/tkt-9a8b09f8e6.test.lua
sql-tap/tkt3346.test.lua
sql-tap/sort.test.lua
sql-tap/delete1.test.lua
sql-tap/index6.test.lua
sql-tap/tkt1514.test.lua
sql-tap/tkt3357.test.lua
sql-tap/gh-3350-skip-scan.test.lua
sql-tap/tkt-54844eea3f.test.lua
sql-tap/tkt2141.test.lua
sql-tap/tkt-7a31705a7e6.test.lua
sql-tap/tkt3424.test.lua
sql-tap/tkt2391.test.lua
sql-tap/e_select1.test.lua
sql-tap/gh2964-abort.test.lua
sql-tap/explain.test.lua
sql-tap/where7.test.lua
sql-tap/where3.test.lua
sql-tap/tkt-4a03edc4c8.test.lua
sql-tap/tkt1443.test.lua
sql-tap/orderby3.test.lua
sql-tap/minmax4.test.lua
sql-tap/where4.test.lua
sql-tap/tkt3527.test.lua
sql-tap/pragma.test.lua
sql-tap/quote.test.lua
sql-tap/orderby8.test.lua
sql-tap/limit.test.lua
sql-tap/unique.test.lua
sql-tap/tkt-d635236375.test.lua
sql-tap/tkt-385a5b56b9.test.lua
sql-tap/select7.test.lua
sql-tap/colname.test.lua
sql-tap/tkt-fc7bd6358f.test.lua
sql-tap/like2.test.lua
sql-tap/keyword1.test.lua
sql-tap/whereD.test.lua
sql-tap/alter.test.lua
sql-tap/minmax3.test.lua
sql-tap/delete4.test.lua
sql-tap/analyze8.test.lua
sql-tap/substr.test.lua
sql-tap/autoindex5.test.lua
sql-tap/eqp.test.lua
sql-tap/orderby2.test.lua
sql-tap/view.test.lua
sql-tap/check.test.lua
sql-tap/selectC.test.lua
sql-tap/tkt-80ba201079.test.lua
sql-tap/contrib01.test.lua
sql-tap/tkt2767.test.lua
sql-tap/sql-errors.test.lua
sql-tap/identifier-characters.test.lua
sql-tap/tkt3841.test.lua
sql-tap/trigger7.test.lua
sql-tap/tkt2927.test.lua
sql-tap/tkt3911.test.lua
sql-tap/index2.test.lua
sql-tap/gh2127-indentifier-max-length.test.lua
sql-tap/tkt2192.test.lua
sql-tap/collation_unicode.test.lua
sql-tap/gh-3251-string-pattern-comparison.test.lua
sql-tap/alter2.test.lua
sql-tap/func.test.lua
sql-tap/selectB.test.lua
sql-tap/count.test.lua
sql-tap/autoinc.test.lua
sql-tap/orderby9.test.lua
sql-tap/coalesce.test.lua
sql-tap/with1.test.lua
sql-tap/default.test.lua
sql-tap/select3.test.lua
sql-tap/unicode.test.lua
sql-tap/intpkey.test.lua
sql-tap/gh2259-in-stmt-trans.test.lua
sql-tap/distinctagg.test.lua
sql-tap/tkt-3a77c9714e.test.lua
sql-tap/fkey3.test.lua
sql-tap/whereF.test.lua
sql-tap/gh-3307-xfer-optimization-issue.test.lua
sql-tap/e_expr.test.lua
sql-tap/gh-3083-ephemeral-unref-tuples.test.lua
sql-tap/lua-tables.test.lua
sql-tap/gh-3332-tuple-format-leak.test.lua
sql-tap/printf2.test.lua
sql-tap/triggerA.test.lua
sql-tap/gh2168-temp-tables.test.lua
sql-tap/triggerD.test.lua
sql-tap/types.test.lua
sql-tap/where5.test.lua
sql-tap/analyzeC.test.lua
sql-tap/gh-4077-iproto-execute-no-bind.test.lua
sql-tap/delete3.test.lua
sql-tap/gh2140-trans.test.lua
sql-tap/analyze3.test.lua
sql-tap/tkt-bd484a090c.test.lua
sql-tap/numcast.test.lua
sql-tap/distinct.test.lua
sql-tap/gh2250-trigger-chain-limit.test.lua
sql-tap/in2.test.lua
app/decimal.test.lua
app/gh-4727-fio-gc.test.lua
app/crypto.test.lua
app/env.test.lua
app/loaders.test.lua
app/buffer.test.lua
app/fiber_cond.test.lua
app/fio.test.lua
app/luafun.test.lua
app/uuid.test.lua
app/crypto_hmac.test.lua
app/strict.test.lua
app/fiber_channel.test.lua
app/fiber.test.lua
app/gh-4662-fiber-storage-leak.test.lua
app/gh-4775-crash-args-l-e.test.lua
app/gh-4076-argparse-wrong-bool-handling.test.lua
app/msgpack.test.lua
app/argparse.test.lua
app/cmdline.test.lua
app/socket.test.lua
app/digest.test.lua
app/pack.test.lua
engine_long/delete_replace_update.test.lua
engine_long/delete_insert.test.lua
replication/box_set_replication_stress.test.lua
replication/autobootstrap.test.lua
replication/status.test.lua
replication/bootstrap_leader.test.lua
replication/gh-4729-netbox-group-id.test.lua
replication/catch.test.lua
replication/replica_rejoin.test.lua
replication/sync.test.lua
replication/join_without_snap.test.lua
replication/show_error_on_disconnect.test.lua
replication/on_schema_init.test.lua
replication/recover_missing_xlog.test.lua
replication/replica_apply_order.test.lua
replication/replicaset_ro_mostly.test.lua
replication/gc_no_space.test.lua
replication/misc.test.lua
replication/long_row_timeout.test.lua
replication/on_replace.test.lua
replication/gh-4606-admin-creds.test.lua
replication/rebootstrap.test.lua
replication/prune.test.lua
replication/gc.test.lua
replication/hot_standby.test.lua
replication/transaction.test.lua
replication/gh-4402-info-errno.test.lua
replication/anon.test.lua
replication/gh-4730-applier-rollback.test.lua
replication/ddl.test.lua
replication/once.test.lua
replication/errinj.test.lua
replication/gh-4605-empty-password.test.lua
replication/gh-4739-vclock-assert.test.lua
replication/before_replace.test.lua
replication/wal_off.test.lua
replication/quorum.test.lua
replication/skip_conflict_row.test.lua
replication/join_vclock.test.lua
replication/local_spaces.test.lua
replication/consistent.test.lua
replication/force_recovery.test.lua
replication/wal_rw_stress.test.lua
replication/autobootstrap_guest.test.lua
wal_off/iterator_lt_gt.test.lua
wal_off/wal_mode.test.lua
wal_off/rtree_benchmark.test.lua
wal_off/expirationd.test.lua
wal_off/oom.test.lua
wal_off/tuple.test.lua
wal_off/alter.test.lua
wal_off/func_max.test.lua
wal_off/snapshot_stress.test.lua
wal_off/lua.test.lua
sql/triggers.test.lua
sql/gh-3199-no-mem-leaks.test.lua
sql/constraint.test.lua
sql/delete-multiple-idx.test.lua
sql/gh2141-delete-trigger-drop-table.test.lua
sql/prepared.test.lua
sql/iproto.test.lua
sql/gh-3888-values-blob-assert.test.lua
sql/select-null.test.lua
sql/delete.test.lua
sql/gh2251-multiple-update.test.lua
sql/bind.test.lua
sql/integer-overflow.test.lua
sql/misc.test.lua
sql/collation.test.lua
sql/upgrade.test.lua
sql/tokenizer.test.lua
sql/gh-2362-select-access-rights.test.lua
sql/drop-index.test.lua
sql/persistency.test.lua
sql/full_metadata.test.lua
sql/max-on-index.test.lua
sql/gh-4745-table-info-assertion.test.lua
sql/transition.test.lua
sql/clear.test.lua
sql/view_delayed_wal.test.lua
sql/gh-3613-idx-alter-update.test.lua
sql/no-pk-space.test.lua
sql/transitive-transactions.test.lua
sql/ddl.test.lua
sql/drop-table.test.lua
sql/update-with-nested-select.test.lua
sql/gh-4546-sql-drop-grants.test.lua
sql/insert-unique.test.lua
sql/errinj.test.lua
sql/message-func-indexes.test.lua
sql/vinyl-opts.test.lua
sql/gh2808-inline-unique-persistency-check.test.lua
sql/sql-statN-index-drop.test.lua
sql/view.test.lua
sql/gh2483-remote-persistency-check.test.lua
sql/engine.test.lua
sql/row-count.test.lua
sql/func-recreate.test.lua
sql/gh-2929-primary-key.test.lua
sql/checks.test.lua
sql/gh-4104-view-access-check.test.lua
sql/gh-2981-check-autoinc.test.lua
sql/gh-4111-format-in-sysview.test.lua
sql/foreign-keys.test.lua
sql/on-conflict.test.lua
sql/gh-3613-idx-alter-update-2.test.lua
sql/check-clear-ephemeral.test.lua
sql/autoincrement.test.lua
sql/savepoints.test.lua
sql/types.test.lua
sql/icu-upper-lower.test.lua"

n_iterations=20
opt="--builddir=build --vardir=build/test/var"
unstable_tests=""

cd build/test

for t in $tests; do
    n_pass=0
    n_fail=0
    echo -n "$t "
    for i in `seq 1 1 $n_iterations`; do
        ../../test/test-run.py $opt $t 2>&1 > /dev/null
        rc=$?
        if test $rc -ne 0; then
            n_fail=$(($n_fail+1))
        fi
    done
    if test $n_fail -ne 0; then
        n_fail=$(($n_fail+1))
        unstable_tests="$unstable_tests $t"
    fi
    echo -n "$n_fail/$n_iterations"
    if test $n_fail -ne 0; then
        echo " FUCK!"
    fi
    echo
done

echo "Flaky tests: " $unstable_tests