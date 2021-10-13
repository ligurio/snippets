-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/
--
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

local checks = require('checks')
local log = require('log')
local fiber = require('fiber')

local function create(self, func)
    checks('table', 'function')

    local id = rawget(self, 'id')
    local ops_generator = rawget(self, 'ops_generator')
    local client = rawget(self, 'client')
    local fiber_obj = fiber.create(func, id, client, ops_generator)
    if fiber_obj ~= box.NULL and fiber_obj:status() ~= 'dead' then
        local name = string.format('jepsen worker %d', id)
        fiber_obj:name(name)
        fiber_obj:wakeup() -- needed for backward compatibility with 1.7
        rawset(self, 'fiber_obj', fiber_obj)
    end
end

local function yield(self)
    checks('table')

    fiber.yield()
end

local function terminate(self)
    checks('table')

    local fiber_obj = rawget(self, 'fiber_obj')
    fiber_obj:kill()
end

-- FIXME: Add timeout.
local function wait_completion(self)
    checks('table')

    local fiber_obj = rawget(self, 'fiber_obj')
    if fiber_obj == box.NULL then
        return
    end

    while fiber_obj:status() ~= 'dead' do
        fiber.yield()
    end  -- the loop is needed for backward compatibility with 1.7
end

local mt = {
    __type = 'Worker',
    __newindex = function()
        error('Worker object is immutable.', 2)
    end,
    __index = {
        create = create,
        terminate = terminate,
        wait_completion = wait_completion,
        yield = yield,
    },
}

local function new(id, client, ops_generator)
    checks('number', 'table', 'function')

    log.info('Running worker %d', id)

    return setmetatable({
        id = id,
        fiber_obj = box.NULL,
        ops_generator = ops_generator,
        client = client,
    }, mt)
end

return {
    new = new,
}
