--[[ Тест для vinyl позволяет случайным образом выставлять error injections,
генерировать операции с индексами, генерировать операции с данными, настройки
vinyl в box.cfg. Все случайные операции и настройки зависят от seed, который
генерируется в самом начале теста.

См. https://github.com/tarantool/tarantool/issues/5076
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
-- debug.sethook(trace, "l")

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

    local n = #t
    local idx = math.random(1, n)
    return t[idx]
end

local errinj_set = {
    ['ERRINJ_VY_GC'] = 'boolean',
    ['ERRINJ_VY_INDEX_DUMP'] = 'double',
    ['ERRINJ_VY_LOG_FLUSH'] = 'boolean',
    ['ERRINJ_VY_LOG_FLUSH_DELAY'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE_DELAY'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE_TIMEOUT'] = 'double',
    ['ERRINJ_VY_RUN_DISCARD'] = 'boolean',
    -- TX: Timed out waiting for Vinyl memory quota.
    -- ['ERRINJ_VY_RUN_WRITE'] = 'boolean',
    ['ERRINJ_VY_RUN_WRITE_DELAY'] = 'boolean',
    ['ERRINJ_VY_SCHED_TIMEOUT'] = 'double',
    ['ERRINJ_VY_SQUASH_TIMEOUT'] = 'double',
    ['ERRINJ_VY_TASK_COMPLETE'] = 'boolean',
}

-- Forward declaration.
local function generate_dml()
end
local function generate_ddl()
end

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

    --[[
    local dump_watermark = 7000000
    while box.stat.vinyl().memory.level0 < dump_watermark do
        generate_insert(space)
    end
    ]]
    log.info('snapshot')
    box.snapshot()
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
        space:create_index('pk', { type = 'tree', parts = {{1, 'uint'}},
                           run_count_per_level = 100,
                           page_size = 128,
                           range_size = 1024 })
        space:create_index('secondary', { unique = false, parts = { 2, 'unsigned' }})
        -- init_space(space)
        spaces[i] = space
    end
    log.info('FINISH SETUP')
end

local function cleanup()
   log.info("CLEANUP")
   os.execute('rm -rf *.snap *.xlog *.vylog')
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

local function index_opts()
    return {
        -- TODO: RTREE
        type = random_elem({'TREE', 'HASH', 'BITSET'}),
        unique = random_elem({true, false}),
        if_not_exists = false,
        -- TODO: index_opts.parts
        -- TODO: dimension (RTREE only)
        -- TODO: distance (RTREE only)
        -- sequence,
        -- func,
        hint = random_elem({true, false}),
        bloom_fpr = math.random(50) / 100,
        -- page_size,
        -- range_size,
        -- run_count_per_level,
        -- run_size_ratio,
    }
end

local function index_create(space)
    local idx_name = 'idx_' .. math.random(100)
    if space.index[idx_name] ~= nil then
        return
    end
    space:create_index(idx_name, index_opts())
end

local function index_drop(space)
    if space.index.i ~= nil then
        space.index.i:drop()
    end
end

local function index_alter(space)
    log.info("INDEX_ALTER")
    space.index[idx_name]:alter(index_opts())
end

local function index_compact(space)
    if space.index.pk ~= nil then
        space.index.pk:compact()
    end
    if space.index.sk ~= nil then
        space.index.sk:compact()
    end
    -- fiber.create(function() space.index.sk:select() end)
    -- space.index.sk:alter{parts = {2, 'number'}}
    -- box.space.stock_reserved.index.primary:select({}, {limit=100})
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
        errinj_val_enable = math.random(0, 10)
        errinj_val_disable = 0
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
