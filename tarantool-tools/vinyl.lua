--[[ Тест для vinyl позволяет случайным образом выставлять error injections,
генерировать операции с индексами, генерировать операции с данными, настройки
vinyl в box.cfg. Все случайные операции и настройки зависят от seed, который
генерируется в самом начале теста.

См. https://github.com/tarantool/tarantool/issues/5076
https://github.com/mkostoevr/tarantool/commit/f3462f6bfb80f93ce2c155bb6444d12e478dd180
https://github.com/tarantool/tarantool/issues/4349

Различие между движками memtx и vinyl,
https://www.tarantool.io/ru/doc/latest/concepts/engines/memtx_vinyl_diff/

Usage:

taskset 0xef ./tarantool vinyl.lua

ASAN=ON LSAN_OPTIONS=suppressions=${PWD}/asan/lsan.supp ASAN_OPTIONS=heap_profile=0:unmap_shadow_on_exit=1:detect_invalid_pointer_pairs=1:symbolize=1:detect_leaks=1:dump_instruction_bytes=1:print_suppressions=0 taskset 0xef ./build/src/tarantool vinyl.lua
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
-- local varbinary = require('varbinary')

local params = require('internal.argparse').parse(arg, {
    { 'engine', 'string' },
    { 'h', 'boolean' },
    { 'seed', 'number' },
    { 'test_duration', 'number' },
    { 'verbose', 'boolean' },
    { 'workers', 'number' },
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

 Usage: tarantool vinyl.lua [options]

 Options can be used with '--', followed by the value if it's not
 a boolean option. The options list with default values:

   workers <number, 50>          - number of fibers to run simultaneously
   test_duration <number, 2*60>  - test duration time (sec)
   engine <string, 'vinyl'>      - engine ('vinyl', 'memtx')
   seed <number>                 - set a PRNG seed
   verbose <boolean, false>      - enable verbose logging
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

local verbose_mode = params.verbose or false

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

local function oneof(tbl)
    assert(type(tbl) == 'table')
    assert(next(tbl) ~= nil)

    local n = table.getn(tbl)
    local idx = math.random(1, n)
    return tbl[idx]
end

local function unique_ids(max_num_ids)
    local ids = {}
    for i = 1, max_num_ids do
        table.insert(ids, i)
    end
    return function()
        local id = math.random(#ids)
        local v = ids[id]
        assert(v)
        table.remove(ids, id)
        return v
    end
end

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

-- local function random_map()
--     local n = math.random(1, 10)
--     local t = {}
--     for i = 1, n do
--         t[tostring(i)] = i
--     end
--     return t
-- end

-- luacheck: ignore
local random_any
local random_scalar

-- '+' - Numeric.
-- '-' - Numeric.
-- '&' - Numeric.
-- '|' - Numeric.
-- '^' - Numeric.
-- '#' - For deletion.
-- '=' - For assignment.
-- ':' - For string splice.
-- '!' - For insertion of a new field.
-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/#indexes-tree
local tarantool_type = {
    -- ['any'] = {
    --     generator = random_any,
    --     operations = {'=', '!'},
    -- },
    ['array'] = {
        generator = random_array,
        operations = {'=', '!'},
        indices = {
            RTREE = true,
        },
    },
    ['boolean'] = {
        generator = function()
            return oneof({true, false})
        end,
        operations = {'=', '!'},
        indices = {
            TREE = true,
            HASH = true,
        },
    },
    ['decimal'] = {
        generator = function()
            return decimal.new(random_int())
        end,
        operations = {'+', '-'},
        indices = {
            TREE = true,
            HASH = true,
        },
    },
    ['datetime'] = {
        generator = function()
            return datetime.new({timestamp = os.time()})
        end,
        operations = {'=', '!'},
        indices = {
            TREE = true,
        },
    },
    ['double'] = {
        generator = function()
            return math.random() * 10^12
        end,
        operations = {'-'},
        indices = {
            TREE = true,
            HASH = true,
        },
    },
    ['integer'] = {
        generator = random_int,
        operations = {'+', '-'},
        indices = {
            TREE = true,
            HASH = true,
        },
    },
    -- ['map'] = {
        -- generator = random_map,
        -- operations = {'=', '!'},
        -- indices = {
        --     RTREE = true,
        -- },
    -- },
    ['number'] = {
        generator = random_int,
        operations = {'+', '-'},
        indices = {
            TREE = true,
            HASH = true,
        },
    },
    -- ['scalar'] = {
        -- generator = random_scalar,
        -- TODO:
        -- operations = {'=', '!'},
        -- indices = {
              -- TREE = true,
              -- HASH = true,
        -- },
    -- },
    ['string'] = {
        generator = rand_string,
        operations = {'=', '!'}, -- XXX: ':'
        indices = {
            TREE = true,
            HASH = true,
            BITSET = true,
        },
    },
    ['unsigned'] = {
        generator = function()
            return math.abs(random_int())
        end,
        operations = {'#', '+', '-', '&', '|', '^'},
        indices = {
            TREE = true,
            HASH = true,
            BITSET = true,
        },
    },
    ['uuid'] = {
        generator = uuid.new,
        operations = {'=', '!'},
        indices = {
            TREE = true,
            HASH = true,
        },
    },
    -- TODO
    -- https://www.tarantool.io/en/doc/latest/how-to/app/cookbook/#ffi-varbinary-insert-lua
    -- ['varbinary'] = {
        -- generator = function()
        --     return varbinary.new(rand_string())
        -- end,
        -- operations = {'=', '!'},
        -- indices = {
		    -- TREE = true,
		    -- HASH = true,
		    -- BITSET = true,
        -- },
    -- },
}

function random_any()
    local t = oneof(keys(tarantool_type))
    return tarantool_type[t].generator
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
    return tarantool_type[t].generator
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

-- Iterator types for indexes.
-- See https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_index/pairs/#box-index-iterator-types
local iterator_type = {
    HASH = {
        'ALL',
        'EQ',
    },
    BITSET = {
        'ALL',
        'BITS_ALL_NOT_SET',
        'BITS_ALL_SET',
        'BITS_ANY_SET',
        'EQ',
    },
    TREE = {
        'ALL',
        'EQ',
        'GE',
        'GT',
        'LE',
        'LT',
        'REQ',
    },
    RTREE = {
        'ALL',
        'EQ',
        'GE',
        'GT',
        'LE',
        'LT',
        'NEIGHBOR',
        'OVERLAPS',
    },
}

local function select_op(space, idx_type, key)
    local select_opts = {
        iterator = oneof(iterator_type[idx_type]),
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

local function get_op(space, key)
    space:get(key)
end

local function put_op(space, tuple)
    space:put(tuple)
end

local function delete_op(space, tuple)
    space:delete(tuple)
end

local function insert_op(space, tuple)
    space:insert(tuple)
end

local function upsert_op(space, tuple, tuple_ops)
    assert(next(tuple_ops) ~= nil)
    space:upsert(tuple, tuple_ops)
end

local function update_op(space, key, tuple_ops)
    assert(next(tuple_ops) ~= nil)
    space:update(key, tuple_ops)
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

local function setup(engine, space_id_func, test_dir, verbose)
    log.info("SETUP")
    local engine_name = engine or oneof({'vinyl', 'memtx'})
    assert(engine_name == 'memtx' or engine_name == 'vinyl')
    -- Configuration reference (box.cfg),
    -- https://www.tarantool.io/en/doc/latest/reference/configuration/
    local box_cfg_options = {
        memtx_memory = 1024 * 1024,
        vinyl_cache = math.random(0, 1000) * 1024 * 1024,
        vinyl_bloom_fpr = math.random(50) / 100,
        vinyl_max_tuple_size = math.random(0, 100000),
        vinyl_memory = 128 * 1024 * 1024,
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
        work_dir = test_dir,
    }
    if verbose then
        box_cfg_options.log_level = 'verbose'
    end
    box.cfg(box_cfg_options)
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

local function teardown(space, dir)
    log.info("TEARDOWN")
    space:drop()
    if dir ~= nil then
        rmtree(dir)
        dir = nil
    end
end

-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/
local function index_opts(space)
    -- FIXME: take into account index options,
    -- see https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/.
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
        local supported_indices = tarantool_type[field.type].indices
        -- Fix "Duplicate key exists in unique index...".
        if supported_indices[opts.type] then
            table.insert(opts.parts, { field.name })
        end
    end
    -- assert(next(opts.parts) ~= nil)
    if next(opts.parts) == nil then
        log.info(space_format)
        log.info(opts.type)
    end

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
    space:create_index(idx_name, opts)
end

local function index_drop_op(space)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:drop() end
end

local function index_alter_op(_, idx, opts)
    assert(idx)
    assert(opts)
    opts.if_not_exists = nil
    idx:alter(opts)
end

local function index_compact_op(_, idx)
    assert(idx)
    idx:compact()
end

local function index_max_op(_, idx)
    assert(idx)
    idx:max()
end

local function index_min_op(_, idx)
    assert(idx)
    idx:min()
end

local function index_random_op(_, idx)
    assert(idx)
    if idx.type ~= 'TREE' then
        idx:random()
    end
end

local function index_rename_op(_, idx, idx_name)
    assert(idx)
    idx:rename(idx_name)
end

local function index_stat_op(_, idx)
    assert(idx)
    idx:stat()
end

local function index_get_op(space, idx, key)
    assert(idx)
    assert(key)
    idx:get(key)
end

local function index_select_op(space, idx, key)
    assert(idx)
    assert(key)
    idx:select(key)
end

local function index_count_op(_, idx)
    assert(idx)
    idx:count()
end

local function index_update_op(space, key, idx, tuple_ops)
    assert(idx)
    assert(key)
    assert(tuple_ops)
    assert(next(tuple_ops) ~= nil)
    idx:update(key, tuple_ops)
end

local function index_delete_op(space, idx, key)
    assert(idx)
    assert(key)
    idx:delete(key)
end

local function random_field_value(field_type)
    local type_gen = tarantool_type[field_type].generator
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
        local operator = oneof(tarantool_type[field_type].operations)
        local value = random_field_value(field_type)
        table.insert(tuple_ops, {operator, field_id, value})
    end

    return tuple_ops
end

local function random_key(space, idx)
    assert(idx, ('indices: %s'):format(json.encode(space.index)))
    local parts = idx.parts
    local key = {}
    for _, field in ipairs(parts) do
        local type_gen = tarantool_type[field.type].generator
        assert(type(type_gen) == 'function')
        table.insert(key, type_gen())
    end
    return key
end

local function box_snapshot()
    local in_progress = box.info.gc().checkpoint_is_in_progress
    if not in_progress then
        box.snapshot()
    end
end

local ops = {
    -- DML.
    DELETE_OP = {
        func = delete_op,
        args = function(space) return random_key(space, space.index[0]) end,
    },
    INSERT_OP = {
        func = insert_op,
        args = function(space) return random_tuple(space:format()) end,
    },
    SELECT_OP = {
        func = select_op,
        args = function(space)
            local idx = space.index[0]
            return idx.type, random_key(space, idx)
        end,
    },
    GET_OP = {
        func = get_op,
        args = function(space) return random_key(space, space.index[0]) end,
    },
    PUT_OP = {
        func = put_op,
        args = function(space) return random_tuple(space:format()) end,
    },
    REPLACE_OP = {
        func = replace_op,
        args = function(space) return random_tuple(space:format()) end,
    },
    UPDATE_OP = {
        func = update_op,
        args = function(space)
            return random_key(space, space.index[0]), random_tuple_operations(space)
        end,
    },
    UPSERT_OP = {
        func = upsert_op,
        args = function(space)
            return random_tuple(space:format()), random_tuple_operations(space)
        end,
    },
    BSIZE_OP = {
        func = bsize_op,
        args = function(_) return end,
    },
    LEN_OP = {
        func = len_op,
        args = function(_) return end,
    },
    -- FORMAT_OP = {
    --     func = format_op,
    --     args = function(space) return { random_space_format() } end,
    -- },

    -- DDL.
    INDEX_ALTER_OP = {
        func = index_alter_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n], index_opts(space)
        end,
    },
    -- INDEX_COMPACT_OP = {
    --     func = index_compact_op,
    --     args = function(space)
    --         local idx_n = oneof(keys(space.index))
    --         return space.index[idx_n]
    --     end,
    -- },
    -- INDEX_CREATE_OP = {
    --     func = index_create_op,
    --     args = function(_) return end,
    -- },
    INDEX_DROP_OP = {
        func = index_drop_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_GET_OP = {
        func = index_get_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return idx, random_key(space, idx)
        end,
    },
    INDEX_SELECT_OP = {
        func = index_select_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return idx, random_key(space, idx)
        end,
    },
    INDEX_MIN_OP = {
        func = index_min_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_MAX_OP = {
        func = index_max_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_RANDOM_OP = {
        func = index_random_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_COUNT_OP = {
        func = index_count_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_UPDATE_OP = {
        func = index_update_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return random_key(space, idx), idx, random_tuple_operations(space)
        end,
    },
    INDEX_DELETE_OP = {
        func = index_delete_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return idx, random_key(space, idx)
        end,
    },
    INDEX_RENAME_OP = {
        func = index_rename_op,
        args = function(space)
            local idx_name = rand_string()
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n], idx_name
        end,
    },
    INDEX_STAT_OP = {
        func = index_stat_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },

    TX_BEGIN = {
        func = function() if not box.is_in_txn() then box.begin() end end,
        args = function(_) return end,
    },
    TX_COMMIT = {
        func = function() if box.is_in_txn() then box.commit() end end,
        args = function(_) return end,
    },
    TX_ROLLBACK = {
        func = function() if box.is_in_txn() then box.rollback() end end,
        args = function(_) return end,
    },

    SNAPSHOT_OP = {
        func = box_snapshot,
        args = function(_) return end,
    },
}

local function apply_op(space, op_name)
    local func = ops[op_name].func
    local args = { ops[op_name].args(space) }
    log.info(('%s %s'):format(op_name, json.encode(args)))
    local pcall_args = {func, space, unpack(args)}
    local ok, err = pcall(unpack(pcall_args))
    if ok ~= true then
        log.info(('ERROR: %s %s'):format(op_name, err))
    end
end

local shared_gen_state

local function worker_func(space, test_gen, test_duration)
    local start = os.clock()
    local gen, param, state = test_gen:unwrap()
    shared_gen_state = state
    while os.clock() - start <= test_duration do
        local operation_name
        state, operation_name = gen(param, shared_gen_state)
        if state == nil then
            break
        end
        shared_gen_state = state
        apply_op(space, operation_name)
        fiber.yield()
    end
end

local function toggle_box_errinj(errinj_name, errinj_set, max_enabled)
    local enabled = fun.iter(errinj_set):
                    filter(function(i, x) if x.is_enabled then return i end end):
                    totable()
    log.info(('Enabled nemeses: %s'):format(json.encode(enabled)))
    local errinj_val
    if table.getn(enabled) >= max_enabled then
        errinj_name = oneof(enabled)
        errinj_val = errinj_set[errinj_name].disable_value
        errinj_set[errinj_name].is_enabled = false
    else
        errinj_val = errinj_set[errinj_name].enable_value
        errinj_set[errinj_name].is_enabled = true
    end
    log.info(string.format("TOGGLE RANDOM ERROR INJECTION: %s -> %s",
                           errinj_name, tostring(errinj_val)))
    box.error.injection.set(errinj_name, errinj_val)
end

local function build_errinj_set()
    local errinj_set = {}
    local errinj = box.error.injection.info()
    for errinj_name, errinj_opt in pairs(errinj) do
        local default_value = errinj[errinj_name].state
        errinj_set[errinj_name] = {
            is_enabled = false,
            enable_value = type(default_value) == 'boolean' and true or math.random(10),
            disable_value = default_value,
        }
        -- See https://github.com/tarantool/tarantool/issues/10033.
        if errinj_name == 'ERRINJ_TUPLE_FIELD_COUNT_LIMIT' then
            errinj_set[errinj_name] = nil
        end
    end

    return errinj_set
end

local function run_test()
    local fibers = {}

    local space_id_func = counter()
    local test_dir = fio.tempdir()
    local space = setup(arg_engine, space_id_func, test_dir, verbose_mode)

    local test_gen = fun.cycle(fun.iter(keys(ops)))
    local f
    for i = 1, arg_num_workers do
        f = fiber.new(worker_func, space, test_gen, arg_test_duration)
        f:set_joinable(true)
        f:name('WRK #' .. i)
        table.insert(fibers, f)
    end

    local errinj_set = build_errinj_set()
    f = fiber.new(function()
        while true do
            local errinj_name = oneof(keys(errinj_set))
            toggle_box_errinj(errinj_name, errinj_set, 2)
            fiber.sleep(0.5)
        end
    end)
    f:set_joinable(true)
    f:name('NEMESES')
    table.insert(fibers, f)

    for _, fb in ipairs(fibers) do
        local ok, errmsg = fiber.join(fb)
        if not ok then
            log.info('ERROR: ' .. errmsg)
        end
    end

    teardown(space, test_dir)
end

run_test()
os.exit(0)
