--[[ Тест для vinyl позволяет случайным образом выставлять error injections,
генерировать операции с индексами, генерировать операции с данными, настройки
vinyl в box.cfg. Все случайные операции и настройки зависят от seed, который
генерируется в самом начале теста.

См. https://github.com/tarantool/tarantool/issues/5076
]]

local TEST_DURATION = 10 * 60
local NUM_SP = 5
local NUM_TUPLES = 1000
local B = 50
local SEED = 10000
local N_OPS_IN_TX = 10

--

local errinj = box.error.injection
local fiber = require('fiber')
local log = require('log')
local math = require('math')
--local inspect = require('inspect')
local seed = SEED or os.time()

log.info(string.format("random seed %d", seed))
seed = seed or math.randomseed(seed)

errinj_set = {'ERRINJ_VY_RUN_WRITE_DELAY',
	      'ERRINJ_VY_RUN_WRITE',
	      'ERRINJ_VY_RUN_WRITE',
	      'ERRINJ_VY_RUN_WRITE_DELAY',
	      'ERRINJ_VY_RUN_DISCARD',
	      'ERRINJ_VY_TASK_COMPLETE',
	      'ERRINJ_VY_READ_PAGE',
	      'ERRINJ_VY_READ_PAGE_DELAY',
	      'ERRINJ_VY_GC',
	      'ERRINJ_VY_LOG_FLUSH',
	      'ERRINJ_VY_LOG_FLUSH_DELAY',
	      'ERRINJ_VY_READ_PAGE_TIMEOUT', -- ERRINJ_DOUBLE, {.dparam = 0}
	      'ERRINJ_VY_SQUASH_TIMEOUT', -- ERRINJ_DOUBLE, {.dparam = 0}
	      'ERRINJ_VY_SCHED_TIMEOUT', -- ERRINJ_DOUBLE, {.dparam = 0}
	      'ERRINJ_VY_INDEX_DUMP'} -- ERRINJ_INT, {.iparam = -1}

function setup(spaces)
    log.info("setup")
    -- TODO: https://www.tarantool.io/en/doc/2.3/reference/configuration/
    box.cfg{listen=3301,
            log_level = 4, 
            memtx_memory=1024*1024*1024,
            vinyl_cache = math.random(),
            -- vinyl_bloom_fpr = math.random(),
            -- vinyl_max_tuple_size = math.random(),
            vinyl_memory=256*1024,
            -- vinyl_page_size = math.random(),
            -- vinyl_range_size = math.random(),
            vinyl_run_size_ratio = math.random(2, 5),
            vinyl_run_count_per_level = math.random(1, 10),
            vinyl_read_threads = math.random(2, 5),
            vinyl_write_threads = math.random(2, 5),
            vinyl_timeout = math.random(1, 60),
            -- checkpoint_interval = 0,
            wal_mode='write'}

    for i = 1, NUM_SP do
        space = box.schema.space.create('test'..i, {engine = 'vinyl'})
        space:create_index('pk', {type='tree', parts={{1, 'uint'}},
                           run_count_per_level = 100,
                           page_size = 128,
                           range_size = 1024})
        space:create_index('secondary', {unique = false, parts = {2, 'unsigned'}})
        init_space(space)
        spaces[i] = space
    end
end;

function teardown(spaces)
   log.info("teardown")
   for i = 1, NUM_SP do
       spaces[i]:drop()
   end
   cleanup()
end;

function cleanup()
   log.info("cleanup")
   os.execute('rm -rf *.snap *.xlog *.vylog')
end;

function init_space(space)
    log.info('creating tuples')
    for j = 1, NUM_TUPLES do
        box.begin()
            for i = 1,N_OPS_IN_TX do
                generate_insert(space)
            end
        box.commit()
    end;

    --[[
    local dump_watermark = 7000000
    while box.stat.vinyl().memory.level0 < dump_watermark do
        generate_insert(space)
    end
    ]]
    log.info('snapshot')
    box.snapshot()
end;

INSERT_OP = 0
DELETE_OP = 1
REPLACE_OP = 2
UPSERT_OP = 3
UPDATE_OP = 4
NO_OP = 5

function generate_op(space)
    log.info("generate_op")
    -- assume no-ops are half of operations
    local op = math.random(0, NO_OP * 2)
    if op == INSERT_OP then
        generate_insert(space)
    elseif op == DELETE_OP then
        generate_delete(space)
    elseif op == REPLACE_OP then
        generate_replace(space)
    elseif op == UPSERT_OP then
        generate_upsert(space)
    elseif op == UPDATE_OP then
        generate_update(space)
    end
end

function index_create(space)
    log.info("index_create")
    --[[
    space:create_index('i')
    space.index.i:alter({bloom_fpr=0.0})
    for i=1,100000 do
        i = i + 1
        space:insert{i,''}
        space.index.i:alter({page_size=i})
    end
    ]]
end

function index_drop()
    log.info("index_drop")
    -- TODO
end

function index_alter()
    log.info("index_alter")
    -- TODO
end

function index_compact()
    log.info("index_compact")
    -- TODO
    -- s.index.pk:compact()
    -- _ = fiber.create(function() s.index.sk:select() end)
    -- s.index.sk:alter{parts = {2, 'number'}}
    -- box.space.stock_reserved.index.primary:select({}, {limit=100})
end

INDEX_CREATE = 0
INDEX_DROP = 1
INDEX_ALTER = 2
INDEX_COMPACT = 3
INDEX_NO_OP = 4

function generate_ddl(space)
    log.info("generate_ddl")
    local idx_op = math.random(0, INDEX_NO_OP * 3)
    if idx_op == INDEX_CREATE then
        index_create(space)
    elseif idx_op == INDEX_DROP then
        index_drop(space)
    elseif idx_op == INDEX_ALTER then
        index_alter(space)
    elseif idx_op == INDEX_COMPACT then
        index_compact(space)
    else
        -- None
    end
end;

TX_COMMIT = 0
TX_ROLLBACK = 1
TX_NOOP = 2

function generate_tx(space)
    log.info("generate_tx")
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
            for i = 1,N_OPS_IN_TX do
                generate_op(space)
            end
        box.commit()
    end
end

function generate_read(space)
    log.info("generate_read")
    -- -- Select from mem.
    -- sk:select{1} -- Ok, found.
    -- -- Dump d2 to disk.
    -- box.snapshot()
    -- -- Select from disk.
    -- sk:select{2} -- !!! Not found !!!.
    --
    -- -- Do fullscan.
    -- sk:select{}
    -- -- Now sk:select{2} works.
    -- sk:select{2}
    --
    space:get(1)
    space:select(1)
    space:select({10}, {iterator = 'ge'})
    space:select({10}, {iterator = 'le'})
    space:select(math.random(count), {iterator = box.index.LE, limit = 10})
end;

function generate_delete(space)
    log.info("generate_delete")
    --space:delete{1, 1}
end;

function generate_insert(space)
    log.info("generate_insert")
    --space:insert(1, math.random(100))

    -- assume that keys are always unsigned
    -- local key = math.random(0, MAX_KEY)
    -- depending on space's format generate corresponding payload
    -- local data = generate_data(space)
    -- space:insert({key, data})

    --[[
    pcall(space.insert, s, {math.random(MAX_KEY), math.random(MAX_VAL),
                        math.random(MAX_VAL), math.random(MAX_VAL), PADDING})
    ]]
end;

function generate_upsert(space)
    log.info("generate_upsert")
    --space:upsert{1, math.random(100)}
end;

function generate_update(space)
    log.info("generate_update")
    --space:update{1, math.random(100)}
end;

function generate_replace(space)
    log.info("generate_replace")
    --space:replace{i, math.random(100)}
end;

function print_stat(spaces)
    log.info("print statistics")
    stat = box.stat.vinyl()
    log.info(string.format('transactions: %d, tx memory: %d',
                    stat.tx.transactions, stat.memory.tx))
    for i = 1, NUM_SP do
        stat = box.space.spaces[i].index.secondary:stat()
        log.info(string.format('memory rows %d bytes %d',
                    stat.memory.rows, stat.memory.bytes))
    end
end

function set_err_injections(n_err_inj_to_set)
    log.info("set random error injections")
    n_err_inj_to_set = n_err_inj_to_set or math.random(0, table.getn(errinj_set))
    for i = 0, n_err_inj_to_set do 
        random_err = errinj_set[math.random(table.getn(errinj_set))]
        log.info(random_err)
        if (random_err == "ERRINJ_VY_INDEX_DUMP") then
            value = math.random(0, 10) -- TODO
        elseif (random_err == "ERRINJ_VY_READ_PAGE_TIMEOUT") then
            value = math.random(0, 10) -- TODO
        elseif (random_err == "ERRINJ_VY_SQUASH_TIMEOUT") then
            value = math.random(0, 10) -- TODO
        elseif (random_err == "ERRINJ_VY_SCHED_TIMEOUT") then
            value = math.random(0, 10) -- TODO
        else
            value = true
        end
        log.info(string.format("set %s -> %s", random_err, tostring(value)))
        errinj.set(random_err, value)
    end
end;

function print_settings()
    -- error injections
    -- general settings
    -- inspect(box.cfg)
end;

function main()
    local spaces = {}
    cleanup()
    setup(spaces)
    set_err_injections(2)
    print_settings()
    box.snapshot()

    --for i = 1,NUM_SP do fiber.create(function() generate_op(spaces[i]) end) end
    --for i = 1,NUM_SP do fiber.create(function() generate_tx(spaces[i]) end) end
    --for i = 1,NUM_SP do fiber.create(function() generate_ddl(spaces[i]) end) end
    -- fiber.create(box.snapshot())

    local start = os.clock()
    while os.clock() - start < TEST_DURATION do
        local n = math.random(1, NUM_SP)
        generate_op(spaces[n])
        generate_tx(spaces[n])
        generate_ddl(spaces[n])
    end;

    teardown(spaces)
end;

main()

require('console').start()
