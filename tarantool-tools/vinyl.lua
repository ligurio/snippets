--[[ Тест для vinyl позволяет случайным образом выставлять error injections,
генерировать операции с индексами, генерировать операции с данными, настройки
vinyl в box.cfg. Все случайные операции и настройки зависят от seed, который
генерируется в самом начале теста.

См. https://github.com/tarantool/tarantool/issues/5076
https://github.com/mkostoevr/tarantool/commit/f3462f6bfb80f93ce2c155bb6444d12e478dd180
https://github.com/tarantool/tarantool/issues/4349

Различие между движками memtx и vinyl,
https://www.tarantool.io/ru/doc/latest/concepts/engines/memtx_vinyl_diff/

Usage: taskset 0xef ./tarantool vinyl.lua
]]

local fiber = require('fiber')
local fio = require('fio')
local fun = require('fun')
local json = require('json')
local log = require('log')
local math = require('math')

-- Tarantool datatypes.
local datetime = require('datetime')
local decimal = require('decimal')
local uuid = require('uuid')
local varbinary = require('varbinary')

local params = require('internal.argparse').parse(arg, {
    { 'engine', 'string' },
    { 'test_duration', 'number' },
    { 'workers', 'number' },
    { 'seed', 'number' },
    { 'h', 'boolean' },
})

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

local function counter()
    local i = 0
    return function() return i + 1 end
end

local index_id_func = counter()

if params.help or params.h then
    print([[

 Usage: taskset 0xef tarantool vinyl.lua [options]

 Options can be used with '--', followed by the value if it's not
 a boolean option. The options list with default values:

   workers <number, 50>          - number of fibers to run simultaneously
   test_duration <number, 2*60>  - test duration time (sec)
   engine <string, 'vinyl'>      - engine ('vinyl', 'memtx')
   seed                          - random seed
   help (same as -h)             - print this message
]])
    os.exit(0)
end

-- Number of workers.
local arg_num_workers = params.workers or 50

-- Test duration time.
local arg_test_duration = params.test_duration or 2*60

-- Tarantool engine.
local arg_engine = params.engine or 'vinyl'

local seed = params.seed or os.time()
math.randomseed(seed)
log.info(string.format("Random seed: %d", seed))

local function keys(t)
    assert(next(t) ~= nil)
    local table_keys = {}
    for k, _ in pairs(t) do
        table.insert(table_keys, k)
    end
    return table_keys
end

local function rmtree(s)
   log.info(("CLEANUP %s"):format(s))
    if (fio.path.is_file(s) or fio.path.is_link(s)) then
        fio.unlink(s)
        return
    end
    if fio.path.is_dir(s) then
        for _, i in pairs(fio.listdir(s)) do
            rmtree(s..'/'..i)
        end
        fio.rmdir(s)
    end
end

local function rand_char()
    return string.char(math.random(97, 97 + 25))
end

local function rand_string(length)
    length = length or 10
    local res = ""
    for _ = 1, length do
        res = res .. rand_char()
    end
    return res
end

local function oneof(t)
    if type(t) ~= 'table' then
        log.info(t)
        error("t is not a table", 3)
    end
    assert(next(t) ~= nil)

    local n = table.getn(t)
    local idx = math.random(1, n)
    return t[idx]
end

local function unique_ids(max_num_ids)
    local ids = {}
    for i = 1, max_num_ids do
        table.insert(ids, i)
    end
    return function()
        -- assert(#ids == 0)
        local id = math.random(#ids)
        local v = ids[id]
        table.remove(ids, id)
        return v
    end
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
local index_create_op

local function random_int()
    return math.floor(math.random() * 10^12)
end

local function random_array()
    local n = math.random(10)
    local t = {}
    for i = 1, n do
        table.insert(t, i)
    end
    return t
end

local function random_map()
    local n = math.random(1, 10)
    local t = {}
    for i = 1, n do
        t[tostring(i)] = i
    end
    return t
end

-- luacheck: ignore
local random_any
local random_scalar

local tarantool_type = {
    ['any'] = random_any,
    ['array'] = random_array,
    ['boolean'] = function() return oneof({true, false}) end,
    ['decimal'] = function() return decimal.new(random_int()) end,
    ['datetime'] = function() return datetime.new({timestamp = os.time()}) end,
    ['double'] = function() return math.random() * 10^12 end,
    ['integer'] = random_int,
    -- ['map'] = random_map,
    ['number'] = random_int,
    -- ['scalar'] = random_scalar,
    ['string'] = rand_string,
    ['unsigned'] = function() return math.abs(random_int()) end,
    ['uuid'] = uuid.new,
    -- TODO
    -- https://www.tarantool.io/en/doc/latest/how-to/app/cookbook/#ffi-varbinary-insert-lua
    -- ['varbinary'] = function() return varbinary.new(rand_string()) end,
}

function random_any()
    local t = oneof(keys(tarantool_type))
    return tarantool_type[t]
end

-- See https://www.tarantool.io/en/doc/latest/concepts/data_model/value_store/#scalar.
function random_scalar()
    local scalars = {
        'boolean',
        'double',
        'integer',
        'number',
        'decimal',
        'uuid',
        -- TODO
        -- 'varbinary',
        'string',
        'unsigned',
    }
    local t = oneof(scalars)
    return tarantool_type[t]
end

-- The name value may be any string, provided that two fields
-- do not have the same name.
-- The type value may be any of allowed types:
-- any | unsigned | string | integer | number | varbinary |
-- boolean | double | decimal | uuid | array | map | scalar,
-- but for creating an index use only indexed fields;
-- (Optional) The is_nullable boolean value specifies whether
-- nil can be used as a field value. See also: key_part.is_nullable.
-- (Optional) The collation string value specifies the collation
-- used to compare field values. See also: key_part.collation.
-- (Optional) The constraint table specifies the constraints that
-- the field value must satisfy.
-- (Optional) The foreign_key table specifies the foreign keys
-- for the field.
--
-- See https://www.tarantool.io/ru/doc/latest/reference/reference_lua/box_space/format/.
local function random_space_format()
    local space_format = {}
    local min_num_fields = 3
    local max_num_fields = 20
    local num_fields = math.random(min_num_fields, max_num_fields)
    for i = 1, num_fields do
        table.insert(space_format, {
            name =('name_%d'):format(i),
            type = oneof(keys(tarantool_type)),
        })
    end
    return space_format
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

local function select_op(space, key)
    local select_opts = {
        iterator = oneof(iter_type),
        -- The maximum number of tuples.
        limit = math.random(100, 500),
        -- The number of tuples to skip.
        offset = math.random(100),
        -- A tuple or the position of a tuple (tuple_pos) after
        -- which select starts the search.
        after = box.NULL,
        -- If true, the select method returns the position of
        -- the last selected tuple as the second value.
        fetch_pos = oneof({true, false}),
    }
    space:select(key, select_opts)
end

local function delete_op(space, tuple)
    space:delete(tuple)
end

local function insert_op(space, tuple)
    space:insert(tuple)
end

local function upsert_op(space, tuple, tuple_ops)
    if next(tuple_ops) ~= nil then
        space:upsert(tuple, tuple_ops)
    end
end

local function update_op(space, key, tuple_ops)
    if next(tuple_ops) ~= nil then
        space:update(key, tuple_ops)
    end
end

local function replace_op(space, tuple)
    space:replace(tuple)
end

local function bsize_op(space)
    space:bsize()
end

local function len_op(space)
    space:len()
end

local function format_op(space, space_format)
    space:format(space_format)
end

local function setup(engine, space_id_func, test_dir)
    log.info("SETUP")
    local engine_name = engine or oneof({'vinyl', 'memtx'})
    assert(engine_name == 'memtx' or engine_name == 'vinyl')
    -- Configuration reference (box.cfg),
    -- https://www.tarantool.io/en/doc/latest/reference/configuration/
    box.cfg{
        memtx_memory = 1024*1024,
        vinyl_cache = math.random(0, 1000) * 1024 * 1024,
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
        wal_mode = oneof({'write', 'fsync'}),
        wal_max_size = math.random(1024 * 1024 * 1024),
        checkpoint_interval = math.random(60),
        checkpoint_count = math.random(5),
        checkpoint_wal_threshold = math.random(1024),
        -- listen = '127.0.0.1:3301',
        worker_pool_threads = math.random(1, 10),
        memtx_use_mvcc_engine = oneof({true, false}),
        memtx_allocator = oneof({'system', 'small'}),
        -- memtx_sort_threads = math.random(1, 256),
        -- slab_alloc_factor = math.random(1, 2),
        -- wal_dir_rescan_delay = math.random(1, 20),
        -- wal_queue_max_size = 16777216,
        -- wal_cleanup_delay = 14400,
        readahead = 16320,
        iproto_threads = math.random(1, 10),
        -- log = ('tarantool-%d.log'):format(seed),
        log_level = 'verbose',
        work_dir = test_dir,
    }
    log.info('FINISH BOX.CFG')

    log.info('CREATE A SPACE')
    local space_opts = {
        engine = engine_name,
        is_local = oneof({true, false}),
        if_not_exists = oneof({true, false}),
        field_count = 0,
        format = random_space_format(),
        -- temporary = oneof({true, false}),
        -- is_sync = oneof({true, false}),
        -- TODO: constraint =
        -- TODO: foreign_key =
    }
    log.info(space_opts)
    local space_name = ('test_%d'):format(space_id_func())
    local space = box.schema.space.create(space_name, space_opts)
    index_create_op(space)
    index_create_op(space)
    log.info('FINISH SETUP')
    return space
end

local function teardown(space)
   log.info("TEARDOWN")
   space:drop()
end

-- local indexed_field_types = {
--     ['TREE'] = {
--         'datetime',
--         'decimal',
--         'double',
--         'integer',
--         'number',
--         'scalar',
--         'string',
--         'unsigned',
--         'uuid',
--         'varbinary',
--     },
--     ['HASH'] = {
--         'decimal',
--         'double',
--         'integer',
--         'number',
--         'scalar',
--         'string',
--         'unsigned',
--         'uuid',
--         'varbinary',
--     },
--     ['BITSET'] = {
--         'scalar',
--         'string',
--         'unsigned',
--         'varbinary',
--     },
--     ['RTREE'] = {
--         'array',
--         'map',
--     },
-- }

-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/#indexes-tree
local indexed_field_types = {
    ['integer'] = {
        ['TREE'] = true,
        ['HASH'] = true,
    },
    ['unsigned'] = {
        ['TREE'] = true,
        ['HASH'] = true,
        ['BITSET'] = true,
    },
    ['double'] = {
        ['TREE'] = true,
        ['HASH'] = true,
    },
    ['number'] = {
        ['TREE'] = true,
        ['HASH'] = true,
    },
    ['decimal'] = {
        ['TREE'] = true,
        ['HASH'] = true,
    },
    ['string'] = {
        ['TREE'] = true,
        ['HASH'] = true,
        ['BITSET'] = true,
    },
    -- ['varbinary'] = {
    --     ['TREE'] = true,
    --     ['HASH'] = true,
    --     ['BITSET'] = true,
    -- },
    ['uuid'] = {
        ['TREE'] = true,
        ['HASH'] = true,
    },
    ['datetime'] = {
        ['TREE'] = true,
    },
    ['array'] = {
        ['RTREE'] = true,
    },
    -- ['scalar'] = {
    --     ['TREE'] = true,
    --     ['HASH'] = true,
    -- },
    ['boolean'] = {
        ['TREE'] = true,
        ['HASH'] = true,
    },
    -- ['map'] = {
    --     ['RTREE'] = true,
    -- },
}

-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/
local function index_opts(space)
    assert(space ~= nil)
    local opts = {
        unique = oneof({true, false}),
        if_not_exists = false,
        -- TODO:
        -- sequence,
        -- func,
        -- page_size,
        -- range_size,
        -- run_count_per_level,
        -- run_size_ratio,
    }

    -- TODO: RTREE, BITSET
    opts.type = oneof({'TREE', 'HASH'})
    if space.engine == 'memtx' then
        opts.hint = oneof({true, false})
    end

    if space.engine == 'vinyl' then
        opts.bloom_fpr = math.random(50) / 100
    end

    opts.parts = {}
    local space_format = space:format()
    local n_parts = math.random(1, table.getn(space_format))
    local id = unique_ids(n_parts)
    for i = 1, n_parts do
        local field_id = id()
        local field = space_format[field_id]
        log.info(field.type)
        local supported_indices = indexed_field_types[field.type]
        -- Fix "Duplicate key exists in unique index...".
        if supported_indices[opts.type] then
            table.insert(opts.parts, { field.name })
        end
    end
    assert(next(opts.parts) ~= nil)

    if opts.type == 'RTREE' then
        opts.dimension = math.random(10)
        opts.distance = oneof({'euclid', 'manhattan'})
    end

    return opts
end

function index_create_op(space)
    local idx_id = index_id_func()
    local idx_name = 'idx_' .. idx_id
    if space.index[idx_name] ~= nil then
        space.index[idx_name]:drop()
    end
    local opts = index_opts(space)
    -- FIXME
    opts.type = 'TREE'
    --  Primary key must be unique.
    if idx_id == 1 then
        opts.unique = true
    end
    local ok, err = pcall(space.create_index, space, idx_name, opts)
    if ok ~= true then
        local msg = ('ERROR: %s (%s)'):format(err, json.encode(opts))
        log.info(msg)
    end
end

local function index_drop_op(space)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:drop() end
end

local function index_alter_op(_, idx, opts)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- local opts = index_opts(space)
    -- -- Option is not relevant.
    -- opts.if_not_exists = nil
    -- if idx ~= nil then idx:alter(opts) end
    opts.if_not_exists = nil
    idx:alter(opts)
end

local function index_compact_op(_, idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- if idx ~= nil then idx:compact() end
    idx:compact()
end

local function index_max_op(_, idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- if idx ~= nil then idx:max() end
    idx:max()
end

local function index_min_op(_, idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- if idx ~= nil then idx:min() end
    idx:min()
end

local function index_random_op(_, idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- if idx ~= nil and
    --    idx.type ~= 'TREE' then
    --     idx:random()
    -- end
    if idx.type ~= 'TREE' then
        idx:random()
    end
end

local function index_rename_op(_, idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    local idx_name = rand_string()
    -- if idx ~= nil then idx:rename(space_name) end
    idx:rename(idx_name)
end

local function index_stat_op(_, idx)
    assert(idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- if idx ~= nil then idx:stat() end
    idx:stat()
end

local function index_get_op(space, key)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:get(key) end
end

local function index_select_op(space, key)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:select(key) end
end

local function index_count_op(_, idx)
    -- if not space.enabled then return end
    -- local idx = oneof(space.index)
    -- if idx ~= nil then idx:count() end
    idx:count()
end

local function index_update_op(space, key, tuple_ops)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:update(key, tuple_ops) end
end

local function index_delete_op(space, tuple)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:delete(tuple) end
end

local function set_err_injection()
    local errinj_name = oneof(keys(errinj_set))
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
        log.info('ERROR: ' .. err)
    end
    fiber.sleep(pause_time)
    log.info(string.format("DISABLE RANDOM ERROR INJECTION: %s -> %s",
                           errinj_name, tostring(errinj_val_disable)))
    ok, err = pcall(box.error.injection.set, errinj_name, errinj_val_disable)
    if ok ~= true then
        log.info('ERROR: ' .. err)
    end
end

local function random_field_value(field_type)
    local type_gen = tarantool_type[field_type]
    assert(type(type_gen) == 'function')
    return type_gen()
end

-- TODO: support is_nullable.
local function random_tuple(space_format)
    local tuple = {}
    for _, field in ipairs(space_format) do
        table.insert(tuple, random_field_value(field.type))
    end

    return tuple
end

-- '+' - Numeric.
-- '-' - Numeric.
-- '&' - Numeric.
-- '|' - Numeric.
-- '^' - Numeric.
-- '#' - For deletion.
-- '=' - For assignment.
-- ':' - For string splice.
-- '!' - For insertion of a new field.
local tuple_op = {
    ['any']        = {'=', '!'},
    ['array']      = {'=', '!'},
    ['boolean']    = {'=', '!'},
    ['decimal']    = {'+', '-'},
    ['datetime']   = {'=', '!'},
    ['double']     = {'-'},
    ['integer']    = {'+', '-'},
    -- ['map']        = {'=', '!'},
    ['number']     = {'+', '-'},
    -- TODO
    -- ['scalar']     = {'=', '!'},
    ['string']     = {'=', '!'}, -- XXX: ':'
    ['unsigned']   = {'#', '+', '-', '&', '|', '^'},
    ['uuid']       = {'=', '!'},
    -- ['varbinary']  = {'=', '!'},
}

-- Example of tuple operations: {{'=', 3, 'a'}, {'=', 4, 'b'}}.
--  - operator (string) – operation type represented in string.
--  - field_identifier (number) – what field the operation will
--    apply to.
--  - value (lua_value) – what value will be applied.
local function random_tuple_operations(space)
    local space_format = space:format()
    local num_fields = math.random(table.getn(space_format))
    local tuple_ops = {}
    local id = unique_ids(num_fields)
    for _ = 1, math.random(num_fields) do
        local field_id = id()
        local field_type = space_format[field_id].type
        log.info(field_type)
        local operator = oneof(tuple_op[field_type])
        local value = random_field_value(field_type)
        table.insert(tuple_ops, {operator, field_id, value})
    end

    return tuple_ops
end

local function random_key(space)
    -- FIXME:
    -- space:op() -- pk
    -- index:op() -- not pk
    local pk = space.index[0]
    assert(pk, ('indices: %s'):format(json.encode(space.index)))
    local parts = pk.parts
    local key = {}
    for _, field in ipairs(parts) do
        local type_gen = tarantool_type[field.type]
        assert(type(type_gen) == 'function')
        table.insert(key, type_gen())
    end
    return key
end

local ops = {
    -- DML
    DELETE_OP = delete_op,
    INSERT_OP = insert_op,
    SELECT_OP = select_op,
    REPLACE_OP = replace_op,
    UPDATE_OP = update_op,
    UPSERT_OP = upsert_op,
    BSIZE_OP = bsize_op,
    LEN_OP = len_op,
    FORMAT_OP = format_op,

    -- DDL
    INDEX_ALTER_OP = index_alter_op,
    INDEX_COMPACT_OP = index_compact_op,
    INDEX_CREATE_OP = index_create_op,
    INDEX_DROP_OP = index_drop_op,
    INDEX_GET_OP = index_get_op,
    INDEX_SELECT_OP = index_select_op,
    INDEX_MIN_OP = index_min_op,
    INDEX_MAX_OP = index_max_op,
    INDEX_RANDOM_OP = index_random_op,
    INDEX_COUNT_OP = index_count_op,
    INDEX_UPDATE_OP = index_update_op,
    INDEX_DELETE_OP = index_delete_op,
    INDEX_RENAME_OP = index_rename_op,
    INDEX_STAT_OP = index_stat_op,

    TX_BEGIN = function() if not box.is_in_txn() then box.begin() end end,
    TX_COMMIT = function() if box.is_in_txn() then box.commit() end end,
    TX_ROLLBACK = function() if box.is_in_txn() then box.rollback() end end,

    SNAPSHOT_OP = function()
        local in_progress = box.info.gc().checkpoint_is_in_progress
        if not in_progress then
            box.snapshot()
        end
    end,
}

local function tarantool_ops_gen(space)
    return fun.cycle(fun.iter({
        -- DML.
        { 'DELETE_OP',   { random_key(space) }},
        { 'INSERT_OP',   { random_tuple(space:format()) }},
        { 'REPLACE_OP',  { random_tuple(space:format()) }},
        { 'SELECT_OP',   { random_key(space) }},
        { 'UPDATE_OP',   { random_key(space), random_tuple_operations(space) }},
        { 'UPSERT_OP',   { random_tuple(space:format()), random_tuple_operations(space) }},

        { 'BSIZE_OP',    { }},
        -- { 'FORMAT_OP',   { random_space_format() }},
        { 'LEN_OP',      { }},

        { 'TX_BEGIN',    { }},
        { 'TX_COMMIT',   { }},
        { 'TX_ROLLBACK', { }},

        -- DDL.
        -- { 'INDEX_ALTER_OP', { oneof(space.index), index_opts(space) }},
        -- { 'INDEX_COMPACT_OP', { oneof(space.index) }},
        -- { 'INDEX_COUNT_OP', { oneof(space.index) }},
        -- { 'INDEX_CREATE_OP', {}},
        -- { 'INDEX_DELETE_OP', { random_tuple(space) }},
        -- { 'INDEX_DROP_OP', {}},
        -- { 'INDEX_GET_OP', { random_key(space) }},
        -- { 'INDEX_MAX_OP', { oneof(space.index) }},
        -- { 'INDEX_MIN_OP', { oneof(space.index) }},
        -- { 'INDEX_RANDOM_OP', { oneof(space.index) }},
        -- { 'INDEX_RENAME_OP', { oneof(space.index) }},
        -- { 'INDEX_SELECT_OP', {}},
        -- { 'INDEX_STAT_OP', { oneof(space.index) }},
        -- { 'INDEX_UPDATE_OP', {}},

        { 'SNAPSHOT_OP', {}},
    }))
end

local function apply_op(space, op)
    log.info(op)
    local op_name = op[1]
    local func = ops[op_name]
    local args = {func, space, unpack(op[2])}
    local ok, err = pcall(unpack(args))
    if ok ~= true then
        log.info('ERROR: ' .. err)
    end
end

local shared_gen_state

local function worker_func(space, test_gen, test_duration)
    local start = os.clock()
    local gen, param, state = test_gen:unwrap()
    shared_gen_state = state
    while os.clock() - start <= test_duration do
        local operation
        state, operation = gen(param, shared_gen_state)
        if state == nil then
            break
        end
        shared_gen_state = state
        apply_op(space, operation)
        fiber.yield()
    end
end

local function run_test()
    local fibers = {}

    local space_id_func = counter()
    local test_dir = fio.tempdir()
    local space = setup(arg_engine, space_id_func, test_dir)

    local test_gen = tarantool_ops_gen(space)
    local f
    for i = 1, arg_num_workers do
        f = fiber.new(worker_func, space, test_gen, arg_test_duration)
        f:set_joinable(true)
        f:name('WRK #' .. i)
        table.insert(fibers, f)
    end

    for _, fb in ipairs(fibers) do
        local ok, errmsg = fiber.join(fb)
        if not ok then
            log.info('ERROR: ' .. errmsg)
        end
    end

    teardown(space)

    if test_dir ~= nil then
        rmtree(test_dir)
        test_dir = nil
    end
end

run_test()
os.exit(0)
