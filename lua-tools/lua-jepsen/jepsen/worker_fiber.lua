-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/

local checks = require('checks')
local log = require('log')
local fiber = require('fiber')

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
local function _start(invoke_func, ops_generator)
    checks('function', 'function')

    local ops_done = 0 -- box.info.lsn
    for _, op in ops_generator() do
        execute_op(invoke_func, op)
        ops_done = ops_done + 1
    end

    return ops_done
end

local function create(self, func)
    log.debug('worker.create()')
    local id = rawget(self, 'id')
    local ops_generator = rawget(self, 'ops_generator')
    local client = rawget(self, 'client')
    local fiber_obj = fiber.create(func, id, client, ops_generator)
    if fiber_obj:status() ~= 'dead' then
        fiber_obj:wakeup() -- needed for backward compatibility with 1.7
        rawset(self, 'fiber_obj', fiber_obj)
    end
end

local function yield(self)
    log.debug('worker.yield()')
    fiber.yield()
end

local function terminate(self)
    log.debug('worker.terminate()')
    local fiber_obj = rawget(self, 'fiber_obj')
    fiber_obj:kill()
end

local function wait_completion(self)
    log.debug('worker.wait_completion')
    --[[
    local fiber_obj = rawget(self, 'fiber_obj')
    while fiber_obj:status() ~= 'dead' do
        fiber.yield()
    end -- the loop is needed for backward compatibility with 1.7
    ]]
    for i = 1, 100000 do
        fiber.yield()
    end
end

local function status(self)
    log.debug('worker.status()')
    local fiber_obj = rawget(self, 'fiber_obj')
    return fiber_obj:status()
end

local mt = {
    __type = 'Worker',
    __newindex = function()
        error('Worker object is immutable.', 2)
    end,
    __index = {
        create = create,
        terminate = terminate,
        status = status,
        wait_completion = wait_completion,
        yield = yield,
    },
}

local function new(id, client, ops_generator)
    checks('number', 'table', 'function')

    return setmetatable({
        id = id,
        fiber_obj = box.NULL,
        ops_generator = ops_generator,
        client = client,
    }, mt)
end

return {
    start = _start,
    new = new,
}
