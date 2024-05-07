--[[ Тест для vinyl позволяет случайным образом выставлять error injections,
генерировать операции с индексами, генерировать операции с данными, настройки
vinyl в box.cfg. Все случайные операции и настройки зависят от seed, который
генерируется в самом начале теста.

См. https://github.com/tarantool/tarantool/issues/5076
]]

local TEST_DURATION = 120 -- Seconds.
local NUM_SP = 5
local NUM_TUPLES = 1000
local SEED = 10000
local N_OPS_IN_TX = 10

--

local fiber = require('fiber')
local log = require('log')
local math = require('math')
local tt_helpers = require('tt_helpers')

local seed = SEED or os.time()
seed = seed or math.randomseed(seed)
log.info(string.format("RANDOM SEED %d", seed))

local function trace(event, line)
    local s = debug.getinfo(2).short_src
    if s == 'vinyl.lua' then
        log.info(s .. ":" .. line)
    end
end

-- https://www.lua.org/pil/23.2.html
-- debug.sethook(trace, "l")

local errinj_set = {
    ['ERRINJ_VY_GC'] = 'boolean',
    ['ERRINJ_VY_INDEX_DUMP'] = 'double',
    ['ERRINJ_VY_LOG_FLUSH'] = 'boolean',
    ['ERRINJ_VY_LOG_FLUSH_DELAY'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE_DELAY'] = 'boolean',
    ['ERRINJ_VY_READ_PAGE_TIMEOUT'] = 'double',
    ['ERRINJ_VY_RUN_DISCARD'] = 'boolean',
    ['ERRINJ_VY_RUN_WRITE'] = 'boolean',
    ['ERRINJ_VY_RUN_WRITE_DELAY'] = 'boolean',
    ['ERRINJ_VY_SCHED_TIMEOUT'] = 'double',
    ['ERRINJ_VY_SQUASH_TIMEOUT'] = 'double',
    ['ERRINJ_VY_TASK_COMPLETE'] = 'boolean',
}

local TX_COMMIT = 0
local TX_ROLLBACK = 1
local TX_NOOP = 2

-- Forward declaration.
local function generate_dml()
end

local function generate_noop()
end

local function generate_tx(space)
    log.info("GENERATE_TX")
    if box.is_in_txn() then
        local tx_op = math.random(0, TX_NOOP * 2)
        if tx_op == TX_COMMIT then
            box.rollback()
        elseif tx_op == TX_ROLLBACK then
            box.commit()
        else
            -- None
        end
    else
        box.begin()
            for i = 1, N_OPS_IN_TX do
                generate_dml(space)
            end
        box.commit()
    end
end

local function generate_read(space)
    log.info("DML: READ")
    box.snapshot()

    -- Do fullscan.
    -- sk:select{}

    space:get(1)
    space:select(1)
    space:select({10}, { iterator = 'ge' })
    space:select({10}, { iterator = 'le' })
    space:select(math.random(count), { iterator = box.index.LE, limit = 10 })
end

local function generate_delete(space)
    log.info("DML: DELETE")
    space:delete({1, 1})
end

local function generate_insert(space)
    log.info("DML: NSERT")

    space:insert(1, math.random(100))
    -- local key = math.random(0, MAX_KEY)
    -- space:insert({key, data})

    pcall(space.insert, space, {math.random(MAX_KEY), math.random(MAX_VAL),
                        math.random(MAX_VAL), math.random(MAX_VAL), PADDING})
end

local function generate_upsert(space)
    log.info("DML: UPSERT")
    space:upsert({1, math.random(100)})
end

local function generate_update(space)
    log.info("DML: UPDATE")
    space:update({1, math.random(100)})
end

local function generate_replace(space)
    log.info("DML: REPLACE")
    local k = math.random(0, 1000)
    space:replace({k, math.random(100)})
end

local function init_space(space)
    log.info('CREATING TUPLES')
    for j = 1, NUM_TUPLES do
        box.begin()
            for i = 1, N_OPS_IN_TX do
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
        -- listen = 3301,
        memtx_memory = 1024*1024,
        vinyl_cache = math.random(0, 10),
        vinyl_bloom_fpr = math.random(0, 0.5),
        vinyl_max_tuple_size = math.random(0, 100000),
        vinyl_memory = 256*1024,
        -- vinyl_page_size = math.random(1, 10),
        -- vinyl_range_size = math.random(1, 10),
        vinyl_run_size_ratio = math.random(2, 5),
        vinyl_run_count_per_level = math.random(1, 10),
        vinyl_read_threads = math.random(2, 5),
        vinyl_write_threads = math.random(2, 5),
        vinyl_timeout = math.random(1, 5),
        checkpoint_interval = 0,
        wal_mode = 'write',
    }
    log.info('FINISH BOX.CFG')

    for i = 1, NUM_SP do
        log.info(i)
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
    ['INSERT_OP'] = generate_insert,
    ['DELETE_OP'] = generate_delete,
    ['REPLACE_OP'] = generate_replace,
    ['UPSERT_OP'] = generate_upsert,
    ['UPDATE_OP'] = generate_update,
    ['NO_OP'] = generate_noop,
}

local function generate_dml(space)
    log.info("GENERATE DML")
    local op_name = tt_helpers.random_elem(tt_helpers.dict_keys(dml_ops))
    log.info(op_name)
	local fn = dml_ops[op_name]
	assert(type(fn) == 'function')
	local ok, err = pcall(fn, space)
	if ok ~= true then
        log.info('ERROR: ' .. err)
	end
end

local function index_create(space)
    log.info("INDEX_CREATE")
    space:create_index('i')
    space.index.i:alter({ bloom_fpr = 0.0 })
    for i = 1, 100000 do
        i = i + 1
        space:insert({ i, '' })
        space.index.i:alter({ page_size = i })
    end
end

local function index_drop(space)
    log.info("INDEX_DROP")
    if space.index.i ~= nil then
        space.index.i:drop()
    end
end

local function index_alter(space)
    log.info("INDEX_ALTER")
    -- TODO
end

local function index_compact(space)
    log.info("INDEX_COMPACT")
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

local function index_noop(space)
    log.info("INDEX_NOOP")
end

local ddl_ops = {
    INDEX_CREATE = index_create,
    INDEX_DROP = index_drop,
    INDEX_ALTER = index_alter,
    INDEX_COMPACT = index_compact,
    INDEX_NO_OP = index_noop,
}

local function generate_ddl(space)
    log.info("GENERATE DDL")
    local op_name = tt_helpers.random_elem(tt_helpers.dict_keys(ddl_ops))
    log.info(op_name)
	local fn = ddl_ops[op_name]
	assert(type(fn) == 'function')
	local ok, err = pcall(fn, space)
	if ok ~= true then
        log.info('ERROR: ' .. err)
	end
end

local function set_err_injection()
    log.info("SET RANDOM ERROR INJECTIONS")
    local errinj_name = tt_helpers.random_elem(tt_helpers.dict_keys(errinj_set))
	local t = errinj_set[errinj_name]

    local errinj_val_enable = true
    local errinj_val_disable = false
    if t == 'double' then
        errinj_val_enable = math.random(0, 10)
        errinj_val_disable = 0
    end
    local pause_time = math.random(1, 20)

    log.info(string.format("SET %s -> %s", errinj_name, tostring(errinj_val_enable)))
    pcall(box.error.injection.set, errinj_name, errinj_val_enable)
    fiber.sleep(pause_time)
    log.info(string.format("SET %s -> %s", errinj_name, tostring(errinj_val_disable)))
    pcall(box.error.injection.set, errinj_name, errinj_val_disable)
end

-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_stat/vinyl/
local function print_stat(spaces)
    log.info("PRINT STATISTICS")
    local stat = box.stat.vinyl()
    log.info(string.format('transactions: %d, tx memory: %d',
                    stat.tx.transactions, stat.memory.tx))
    for i = 1, NUM_SP do
        stat = spaces[i].index.secondary:stat()
        log.info(string.format('memory rows %d bytes %d',
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
