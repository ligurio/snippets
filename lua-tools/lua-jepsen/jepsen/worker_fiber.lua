-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/fiber/
--
local fiber = require('fiber')

local dev_checks = require('jepsen.dev_checks')
local log = require('jepsen.log')

local function spawn(self, func)
    dev_checks('table', 'function')

    local id = self.id
    local ops_generator = self.ops_generator
    local client = self.client
    local fiber_obj = fiber.new(func, id, client, ops_generator)
    if fiber_obj:status() ~= 'dead' then
        fiber_obj:set_joinable(true)
        fiber_obj:name(string.format('worker %d', id))
        fiber_obj:wakeup() -- needed for backward compatibility with 1.7
        rawset(self, 'fiber_obj', fiber_obj)
    end

    return true
end

local function yield(self)
    dev_checks('table')

    if self.fiber_obj ~= nil and self.fiber_obj:status() ~= 'dead' then
        fiber.yield()
    end

    return true
end

local function terminate(self)
    dev_checks('table')

    if self.fiber_obj ~= nil and self.fiber_obj:status() ~= 'dead' then
        self.fiber_obj:kill()
    end

    return true
end

local function wait_completion(self)
    dev_checks('table')

    if self.fiber_obj ~= nil and self.fiber_obj:status() ~= 'dead' then
        self.fiber_obj:join()
    end

    return true
end

local mt = {
    __type = '<worker>',
    __tostring = function(self)
        return '<worker>'
    end,
    __newindex = function()
        error('Worker object is immutable.', 2)
    end,
    __index = {
        spawn = spawn,
        terminate = terminate,
        wait_completion = wait_completion,
        yield = yield,
    },
}

local function new(id, client, ops_generator)
    dev_checks('number', 'function', 'function')

    log.info('Running a worker %d', id)

    return setmetatable({
        id = id,
        ops_generator = ops_generator,
        client = client,
    }, mt)
end

return {
    new = new,
}
