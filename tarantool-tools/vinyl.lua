--[[ Тест для vinyl позволяет случайным образом выставлять error injections,
генерировать операции с индексами, генерировать операции с данными, настройки
vinyl в box.cfg. Все случайные операции и настройки зависят от seed, который
генерируется в самом начале теста.

См. https://github.com/tarantool/tarantool/issues/5076
https://github.com/mkostoevr/tarantool/commit/f3462f6bfb80f93ce2c155bb6444d12e478dd180
https://github.com/tarantool/tarantool/issues/4349
]]

local TEST_DURATION = 10*60 -- Seconds.
local NUM_SP = 5
local NUM_TUPLES = 1000
local SEED = 10000
local N_OPS_IN_TX = 10
local MAX_KEY = 10000

--

local fiber = require('fiber')
local log = require('log')
local math = require('math')

local seed = SEED or os.time()
seed = seed or math.randomseed(seed)
log.info(string.format("RANDOM SEED %d", seed))

local function trace(event, line) -- luacheck: no unused
    local s = debug.getinfo(2).short_src
    if s == 'vinyl.lua' then
        log.info(s .. ":" .. line)
    end
end

-- https://www.lua.org/pil/23.2.html
if os.getenv('DEV') then
    debug.sethook(trace, "l")
end

local function dict_keys(t)
    assert(next(t) ~= nil)
    local keys = {}
    for k, _ in pairs(t) do
        table.insert(keys, k)
    end
	return keys
end

-- local function rand_char()
--     return string.char(math.random(97, 97 + 25))
-- end

local function random_elem(t)
    assert(type(t) == 'table')
    assert(next(t) ~= nil)

    local n = table.getn(t)
    local idx = math.random(1, n)
    return t[idx]
end

-- TODO: Obtain error injections dynamically:
-- box.error.injection.info()
-- box.error.injection.get('ERRINJ_SNAP_SKIP_ALL_ROWS')
-- box.error.injection.set('ERRINJ_SNAP_SKIP_ALL_ROWS', true)
-- Source: src/lib/core/errinj.h
local errinj_set = {
    ['ERRINJ_APPLIER_DESTROY_DELAY'] = 'boolean',
    ['ERRINJ_APPLIER_READ_TX_ROW_DELAY'] = 'boolean',
    ['ERRINJ_APPLIER_SLOW_ACK'] = 'boolean',
    ['ERRINJ_APPLIER_STOP_DELAY'] = 'boolean',
    ['ERRINJ_BUILD_INDEX'] = 'int',
    ['ERRINJ_BUILD_INDEX_DELAY'] = 'boolean',
    ['ERRINJ_BUILD_INDEX_ON_ROLLBACK_ALLOC'] = 'boolean',
    ['ERRINJ_BUILD_INDEX_TIMEOUT'] = 'double',
    ['ERRINJ_CHECK_FORMAT_DELAY'] = 'boolean',
    ['ERRINJ_COIO_SENDFILE_CHUNK'] = 'int',
    ['ERRINJ_COIO_WRITE_CHUNK'] = 'boolean',
    ['ERRINJ_DYN_MODULE_COUNT'] = 'int',
    ['ERRINJ_ENGINE_JOIN_DELAY'] = 'boolean',
    ['ERRINJ_FIBER_MADVISE'] = 'boolean',
    ['ERRINJ_FIBER_MPROTECT'] = 'int',
    ['ERRINJ_FLIGHTREC_RECREATE_RENAME'] = 'boolean',
    ['ERRINJ_FLIGHTREC_LOG_DELAY'] = 'double',
    ['ERRINJ_HTTPC_EXECUTE'] = 'boolean',
    ['ERRINJ_HTTP_RESPONSE_ADD_WAIT'] = 'boolean',
    ['ERRINJ_INDEX_ALLOC'] = 'boolean',
    ['ERRINJ_INDEX_RESERVE'] = 'boolean',
    ['ERRINJ_INDEX_ITERATOR_NEW'] = 'boolean',
    ['ERRINJ_HASH_INDEX_REPLACE'] = 'boolean',
    ['ERRINJ_IPROTO_CFG_LISTEN'] = 'boolean',
    ['ERRINJ_IPROTO_DISABLE_ID'] = 'boolean',
    ['ERRINJ_IPROTO_DISABLE_WATCH'] = 'boolean',
    ['ERRINJ_IPROTO_FLIP_FEATURE'] = 'int',
    ['ERRINJ_IPROTO_SET_VERSION'] = 'int',
    ['ERRINJ_IPROTO_TX_DELAY'] = 'boolean',
    ['ERRINJ_IPROTO_WRITE_ERROR_DELAY'] = 'boolean',
    ['ERRINJ_LOG_ROTATE'] = 'boolean',
    ['ERRINJ_MEMTX_DELAY_GC'] = 'boolean',
    ['ERRINJ_NETBOX_DISABLE_ID'] = 'boolean',
    ['ERRINJ_NETBOX_FLIP_FEATURE'] = 'int',
    ['ERRINJ_NETBOX_IO_DELAY'] = 'boolean',
    ['ERRINJ_NETBOX_IO_ERROR'] = 'boolean',
    ['ERRINJ_RAFT_WAIT_TERM_PERSISTED_DELAY'] = 'boolean',
    ['ERRINJ_RELAY_BREAK_LSN'] = 'int',
    ['ERRINJ_RELAY_EXIT_DELAY'] = 'double',
    ['ERRINJ_RELAY_FASTER_THAN_TX'] = 'boolean',
    ['ERRINJ_RELAY_FINAL_JOIN'] = 'boolean',
    ['ERRINJ_RELAY_FINAL_SLEEP'] = 'boolean',
    ['ERRINJ_RELAY_FROM_TX_DELAY'] = 'boolean',
    ['ERRINJ_RELAY_REPORT_INTERVAL'] = 'double',
    ['ERRINJ_RELAY_SEND_DELAY'] = 'boolean',
    ['ERRINJ_RELAY_TIMEOUT'] = 'double',
    ['ERRINJ_RELAY_WAL_START_DELAY'] = 'boolean',
    ['ERRINJ_REPLICASET_VCLOCK'] = 'boolean',
    ['ERRINJ_REPLICA_JOIN_DELAY'] = 'boolean',
    ['ERRINJ_SIGILL_MAIN_THREAD'] = 'boolean',
    ['ERRINJ_SIGILL_NONMAIN_THREAD'] = 'boolean',
    ['ERRINJ_SIO_READ_MAX'] = 'int',
    ['ERRINJ_SNAP_COMMIT_DELAY'] = 'boolean',
    ['ERRINJ_SNAP_COMMIT_FAIL'] = 'boolean',
    ['ERRINJ_SNAP_SKIP_ALL_ROWS'] = 'boolean',
    ['ERRINJ_SNAP_SKIP_DDL_ROWS'] = 'boolean',
    ['ERRINJ_SNAP_WRITE_DELAY'] = 'boolean',
    ['ERRINJ_SNAP_WRITE_CORRUPTED_INSERT_ROW'] = 'boolean',
    ['ERRINJ_SNAP_WRITE_INVALID_SYSTEM_ROW'] = 'boolean',
    ['ERRINJ_SNAP_WRITE_MISSING_SPACE_ROW'] = 'boolean',
    ['ERRINJ_SNAP_WRITE_TIMEOUT'] = 'double',
    ['ERRINJ_SNAP_WRITE_UNKNOWN_ROW_TYPE'] = 'boolean',
    ['ERRINJ_SPACE_UPGRADE_DELAY'] = 'boolean',
    ['ERRINJ_SWIM_FD_ONLY'] = 'boolean',
    ['ERRINJ_TESTING'] = 'boolean',
    ['ERRINJ_TUPLE_ALLOC'] = 'boolean',
    ['ERRINJ_TUPLE_FIELD'] = 'boolean',
    -- https://github.com/tarantool/tarantool/issues/10033
    -- ['ERRINJ_TUPLE_FIELD_COUNT_LIMIT'] = 'int',
    ['ERRINJ_TUPLE_FORMAT_COUNT'] = 'int',
    ['ERRINJ_TX_DELAY_PRIO_ENDPOINT'] = 'double',
    ['ERRINJ_TXN_COMMIT_ASYNC'] = 'boolean',
    ['ERRINJ_TXN_LIMBO_BEGIN_DELAY'] = 'boolean',
    ['ERRINJ_VYRUN_DATA_READ'] = 'boolean',
    ['ERRINJ_VY_COMPACTION_DELAY'] = 'boolean',
    ['ERRINJ_VY_DELAY_PK_LOOKUP'] = 'boolean',
    ['ERRINJ_VY_DUMP_DELAY'] = 'boolean',
    ['ERRINJ_VY_GC'] = 'boolean',
    ['ERRINJ_VY_INDEX_DUMP'] = 'int',
    ['ERRINJ_VY_INDEX_FILE_RENAME'] = 'boolean',
    ['ERRINJ_VY_LOG_FILE_RENAME'] = 'boolean',
    ['ERRINJ_VY_LOG_FLUSH'] = 'boolean',
    ['ERRINJ_VY_POINT_ITER_WAIT'] = 'boolean',
    ['ERRINJ_VY_QUOTA_DELAY'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE_DELAY'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE_TIMEOUT'] = 'double',
    ['ERRINJ_VY_READ_VIEW_MERGE_FAIL'] = 'boolean',
    ['ERRINJ_VY_RUN_DISCARD'] = 'boolean',
    ['ERRINJ_VY_RUN_FILE_RENAME'] = 'boolean',
    ['ERRINJ_VY_RUN_OPEN'] = 'int',
    ['ERRINJ_VY_RUN_WRITE'] = 'boolean',
    ['ERRINJ_VY_RUN_WRITE_DELAY'] = 'boolean',
    ['ERRINJ_VY_RUN_WRITE_STMT_TIMEOUT'] = 'double',
    ['ERRINJ_VY_SCHED_TIMEOUT'] = 'double',
    ['ERRINJ_VY_SQUASH_TIMEOUT'] = 'double',
    ['ERRINJ_VY_STMT_ALLOC'] = 'int',
    ['ERRINJ_VY_TASK_COMPLETE'] = 'boolean',
    ['ERRINJ_VY_WRITE_ITERATOR_START_FAIL'] = 'boolean',
    ['ERRINJ_WAIT_QUORUM_COUNT'] = 'int',
    ['ERRINJ_WAL_BREAK_LSN'] = 'int',
    ['ERRINJ_WAL_DELAY'] = 'boolean',
    ['ERRINJ_WAL_DELAY_COUNTDOWN'] = 'int',
    ['ERRINJ_WAL_FALLOCATE'] = 'int',
    ['ERRINJ_WAL_IO'] = 'boolean',
    ['ERRINJ_WAL_IO_COUNTDOWN'] = 'int',
    ['ERRINJ_WAL_ROTATE'] = 'boolean',
    ['ERRINJ_WAL_SYNC'] = 'boolean',
    ['ERRINJ_WAL_SYNC_DELAY'] = 'boolean',
    ['ERRINJ_WAL_WRITE'] = 'boolean',
    ['ERRINJ_WAL_WRITE_COUNT'] = 'int',
    ['ERRINJ_WAL_WRITE_DISK'] = 'boolean',
    ['ERRINJ_WAL_WRITE_EOF'] = 'boolean',
    ['ERRINJ_WAL_WRITE_PARTIAL'] = 'int',
    ['ERRINJ_XLOG_GARBAGE'] = 'boolean',
    ['ERRINJ_XLOG_META'] = 'boolean',
    ['ERRINJ_XLOG_READ'] = 'int',
    ['ERRINJ_XLOG_RENAME_DELAY'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_CORRUPTED_BODY'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_CORRUPTED_HEADER'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_INVALID_BODY'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_INVALID_HEADER'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_INVALID_KEY'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_INVALID_VALUE'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_UNKNOWN_KEY'] = 'boolean',
    ['ERRINJ_XLOG_WRITE_UNKNOWN_TYPE'] = 'boolean',
}

-- Forward declaration.
local function generate_dml() end
local function generate_ddl() end

local tx_op = {
    ['TX_COMMIT'] = function() box.rollback() end,
    ['TX_ROLLBACK'] = function() box.commit() end,
    ['TX_NOOP'] = function() end,
}

local function generate_tx(space)
    log.info("GENERATE_TX")
    if box.is_in_txn() then
        local tx_op_name = random_elem(dict_keys(tx_op))
	    local fn = tx_op[tx_op_name]
	    assert(type(fn) == 'function')
	    pcall(fn)
    else
        box.begin()
            for _ = 1, N_OPS_IN_TX do
                generate_dml(space)
                generate_ddl(space)
            end
        box.commit()
    end
end

-- Iterator types for TREE indexes.
-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_index/pairs/#box-index-iterator-types
local iter_type = {
    'ALL',
    'EQ',
    'GE',
    'GT',
    'LE',
    'LT',
    'REQ',
}

local function generate_read(space)
    box.snapshot()

    space:get(1)
    local select_opts = {
        iterator = random_elem(iter_type),
        -- The maximum number of tuples.
        limit = math.random(5000),
        -- The number of tuples to skip.
        offset = math.random(100),
        -- A tuple or the position of a tuple (tuple_pos) after
        -- which select starts the search.
        after = box.NULL,
        -- If true, the select method returns the position of
        -- the last selected tuple as the second value.
        fetch_pos = random_elem({true, false}),
    }
    log.info(select_opts)
    space:select(math.random(MAX_KEY), select_opts)
end

local function generate_delete(space)
    local key = math.random(MAX_KEY)
    space:delete(key)
end

local function generate_insert(space)
    local key = math.random(MAX_KEY)
    if space:get(key) ~= nil then
        return
    end
    pcall(space.insert, space, {
        key,
		math.random(MAX_KEY),
        math.random(MAX_KEY),
        math.random(MAX_KEY),
	})
end

local tuple_op = {
    '+', -- numeric.
    '-', -- numeric.
    '&', -- numeric.
    '|', -- numeric.
    '^', -- numeric.
    '!', -- for insertion of a new field.
    '#', -- for deletion.
    '=', -- for assignment.
    -- ':', for string splice.
}

local function generate_upsert(space)
    local tuple = { math.random(1000), math.random(1000) }
    space:upsert(tuple, {
        { random_elem(tuple_op), math.random(2), math.random(1000) },
        { random_elem(tuple_op), math.random(2), math.random(1000) }
    })
end

local function generate_update(space)
    local count = space:count()
	space:update(math.random(count), {
        { random_elem(tuple_op), math.random(2), math.random(1000) },
        { random_elem(tuple_op), math.random(2), math.random(1000) },
    })
end

local function generate_replace(space)
    local k = math.random(0, 1000)
    space:replace({k, math.random(100)})
end

local function init_space(space)
    log.info('CREATING TUPLES')
    for _ = 1, NUM_TUPLES do
        box.begin()
            for _ = 1, N_OPS_IN_TX do
                generate_insert(space)
            end
        box.commit()
    end
    local dump_watermark = 70000
    while box.stat.vinyl().memory.level0 < dump_watermark do
        generate_insert(space)
    end
end

local function setup(spaces)
    log.info("SETUP")
    -- TODO: https://www.tarantool.io/en/doc/2.3/reference/configuration/
    box.cfg{
        memtx_memory = 1024*1024,
        vinyl_cache = math.random(0, 10),
        vinyl_bloom_fpr = math.random(50) / 100,
        vinyl_max_tuple_size = math.random(0, 100000),
        vinyl_memory = 10*1024*1024,
        -- vinyl_page_size = math.random(1, 10),
        -- vinyl_range_size = math.random(1, 10),
        vinyl_run_size_ratio = math.random(2, 5),
        vinyl_run_count_per_level = math.random(1, 10),
        vinyl_read_threads = math.random(2, 10),
        vinyl_write_threads = math.random(2, 10),
        vinyl_timeout = math.random(1, 5),
        wal_mode = random_elem({'write', 'fsync'}),
        wal_max_size = math.random(1024 * 1024 * 1024),
        checkpoint_interval = math.random(1*60*60),
        checkpoint_count = math.random(5),
        checkpoint_wal_threshold = math.random(10^18),
    }
    log.info('FINISH BOX.CFG')

    for i = 1, NUM_SP do
        log.info('create space ' .. tostring(i))
        local space = box.schema.space.create('test' .. i, { engine = 'vinyl' })
        -- TODO: replace with function create_index.
        space:create_index('pk', { type = 'tree', parts = {{1, 'uint'}},
                           run_count_per_level = 100,
                           page_size = 128,
                           range_size = 1024 })
        -- TODO: replace with function create_index.
        space:create_index('secondary', { unique = false, parts = { 2, 'unsigned' }})
        init_space(space)
        spaces[i] = space
    end
    log.info('FINISH SETUP')
end

local function cleanup()
   log.info("CLEANUP")
   os.execute('rm -rf *.snap *.xlog *.vylog 51*')
end

local function teardown(spaces)
   log.info("TEARDOWN")
   for i = 1, NUM_SP do
       spaces[i]:drop()
   end
   cleanup()
end

local dml_ops = {
    ['DELETE_OP'] = generate_delete,
    ['INSERT_OP'] = generate_insert,
    ['READ_OP'] = generate_read,
    ['REPLACE_OP'] = generate_replace,
    ['UPDATE_OP'] = generate_update,
    ['UPSERT_OP'] = generate_upsert,
}

generate_dml = function(space)
    local op_name = random_elem(dict_keys(dml_ops))
    log.info(("GENERATE DML: %s"):format(op_name))
	local fn = dml_ops[op_name]
	assert(type(fn) == 'function')
	local ok, err = pcall(fn, space)
	if ok ~= true then
        log.info('ERROR: ' .. err)
	end
end

-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/
local function index_opts(space)
    assert(space ~= nil)
    local opts = {
        unique = random_elem({true, false}),
        if_not_exists = false,
        -- sequence,
        -- func,
        -- page_size,
        -- range_size,
        -- run_count_per_level,
        -- run_size_ratio,
    }

    -- TODO: RTREE, BITSET
    opts.type = random_elem({'TREE', 'HASH'})
    if space.engine == 'memtx' then
        opts.hint = random_elem({true, false})
    end

    if space.engine == 'vinyl' then
        opts.bloom_fpr = math.random(50) / 100
    end

    -- TODO: index_opts.parts

    if opts.type == 'RTREE' then
        -- TODO: dimension (RTREE only)
    end
    if opts.type == 'RTREE' then
        -- TODO: distance (RTREE only)
    end

    return opts
end

local function index_create(space)
    local idx_name = 'idx_' .. math.random(100)
    if space.index[idx_name] ~= nil then
        space.index[idx_name]:drop()
    end
    local opts = index_opts(space)
    local ok, err = pcall(space.create_index, space, idx_name, opts)
    if ok ~= true then
        log.info('ERROR: ' .. err)
        log.info(opts)
    end
end

local function index_drop(space)
    if space.index.i ~= nil then
        space.index.i:drop()
    end
end

local function index_alter(space)
    local idx = random_elem(space.index)
    local opts = index_opts(space)
    -- Option is not relevant.
    opts.if_not_exists = nil
    idx:alter(opts)
    -- TODO: space.index.sk:alter{parts = {2, 'number'}}
end

local function index_compact(space)
    if space.index.pk ~= nil then
        space.index.pk:compact()
    end
    if space.index.sk ~= nil then
        space.index.sk:compact()
    end
end

local function index_noop()
    -- Nope.
end

local ddl_ops = {
    INDEX_ALTER = index_alter,
    INDEX_COMPACT = index_compact,
    INDEX_CREATE = index_create,
    INDEX_DROP = index_drop,
    INDEX_NO_OP = index_noop,
}

generate_ddl = function(space)
    local op_name = random_elem(dict_keys(ddl_ops))
    log.info(("GENERATE DDL: %s"):format(op_name))
	local fn = ddl_ops[op_name]
	assert(type(fn) == 'function')
	local ok, err = pcall(fn, space)
	if ok ~= true then
        log.info('ERROR: ' .. err)
	end
end

local function set_err_injection()
    local errinj_name = random_elem(dict_keys(errinj_set))
	local t = errinj_set[errinj_name]

    local errinj_val_enable = true
    local errinj_val_disable = false
    if t == 'double' then
        errinj_val_enable = math.random(0, 50)
        errinj_val_disable = 0
    end
    if t == 'int' then
        errinj_val_enable = math.random(0, 50)
        errinj_val_disable = -1
    end

    local pause_time = math.random(1, 10)

    log.info(string.format("ENABLE RANDOM ERROR INJECTION: %s -> %s",
                           errinj_name, tostring(errinj_val_enable)))
    local ok, err
    ok, err = pcall(box.error.injection.set, errinj_name, errinj_val_enable)
    if ok ~= true then
        log.info(err)
    end
    fiber.sleep(pause_time)
    log.info(string.format("DISABLE RANDOM ERROR INJECTION: %s -> %s",
                           errinj_name, tostring(errinj_val_disable)))
    ok, err = pcall(box.error.injection.set, errinj_name, errinj_val_disable)
    if ok ~= true then
        log.info('ERR: ' .. err)
    end
end

-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_stat/vinyl/
local function print_stat(spaces)
    log.info("PRINT STATISTICS")
    local stat = box.stat.vinyl()
    log.info(string.format('STATISTICS: transactions: %d, tx memory: %d',
                           stat.tx.transactions, stat.memory.tx))
    for i = 1, NUM_SP do
        stat = spaces[i].index.secondary:stat()
        log.info(string.format('STATISTICS: memory rows %d bytes %d',
                               stat.memory.rows, stat.memory.bytes))
    end
end

local function main()
    local spaces = {}

    cleanup()
    setup(spaces)

    local f
    for i = 1, NUM_SP do
        f = fiber.create(function()
            log.info('START DML ' .. i)
            while true do generate_dml(spaces[i]); fiber.yield() end
        end)
        f:name('DML_' .. i)
    end

    for i = 1, NUM_SP do
        f = fiber.create(function()
            log.info('START TX ' .. i)
            while true do
                local ok, err = pcall(generate_tx, spaces[i])
                if ok ~= true then
                    log.info('TX: ' .. err)
                end
                fiber.yield()
            end
        end)
        f:name('TX_' .. i)
    end

    for i = 1, NUM_SP do
        f = fiber.create(function()
            log.info('START DDL ' .. i)
            while true do generate_ddl(spaces[i]); fiber.yield() end
        end)
        f:name('DDL_' .. i)
    end

    f = fiber.create(function()
        while true do
            local ok, err = pcall(box.snapshot)
            if ok ~= true then
                log.info('BOX SNAPSHOT: ' .. err)
            end; fiber.sleep(5)
        end
    end)
    f:name('snapshots')

    f = fiber.create(function()
        while true do set_err_injection(); fiber.sleep(5) end
    end)
    f:name('ERRINJ')

    f = fiber.create(function()
        while true do print_stat(spaces); fiber.sleep(5) end
    end)
    f:name('STATS')

    local start = os.clock()
    while os.clock() - start < TEST_DURATION do
        local n = math.random(1, NUM_SP)
        generate_dml(spaces[n])
        generate_tx(spaces[n])
        generate_ddl(spaces[n])
    end

    teardown(spaces)
end

main()

require('console').start()
