-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/

local checks = require('checks')
local log = require('log')

local utils = require('jepsen.utils')

local function execute_op(func, op)
    checks('function', {
        f = 'string',
        v = '?'
    })
    log.info('[jepsen worker] %s', utils.op_to_string(op))
    local ok, res = pcall(func, op)
    if not ok then
        log.info(res)
    else
        assert(res.state ~= nil)
        assert(res.f ~= nil)
        log.info('[jepsen worker] %s',  utils.op_to_string(res))
    end
end

-- 3  :ok     :transfer   {:from 8, :to 2, :amount 3}
-- 0  :ok     :transfer   {:from 1, :to 9, :amount 1}
-- 0  :invoke :transfer   {:from 3, :to 9, :amount 5}
-- 4  :ok     :read       {0 5, 1 10, 2 12, 3 10, 4 11, 5 5, 6 20, 7 0, 8 10, 9 17}
-- 4  :invoke :read       nil
-- 3  :ok     :read       {0 5, 1 9, 2 12, 3 10, 4 11, 5 5, 6 20, 7 0, 8 10, 9 18}
-- 3  :invoke :read       nil
--
-- state can be nil (invoke), true (ok) or false (fail)
-- f is defined by user
-- v is defined by user
local function start_worker(invoke_func, ops_generator)
    checks('function', 'function')

    local ops_done = 0 -- box.info.lsn
    for _, op in ops_generator() do
        execute_op(invoke_func, op)
        ops_done = ops_done + 1
    end

    return ops_done
end

local function start()
end

local function stop()
end

local mt = {
    __type = 'worker',
    __newindex = function()
        error('Worker object is immutable.', 2)
    end,
    __index = {
        start = start,
        stop = stop,
    },
}

local function new(id, client, opts)
    return setmetatable({
        id = id,
        opts = opts,
        client = client,
    }, mt)
end

return {
    start_worker = start_worker,
    new = new,
}
