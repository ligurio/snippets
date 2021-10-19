-- http://www.lua.org/pil/9.1.html
-- TODO:
-- https://gist.github.com/Deco/1818054
-- https://github.com/starwing/luasched
-- http://lua-users.org/files/wiki_insecure/users/twrensch/play.lua
-- https://mode13h.io/coroutines-scheduler-in-lua/

local fiber = require('fiber')

local dev_checks = require('jepsen.dev_checks')
local log = require('jepsen.log')

local function spawn(self, func)
    dev_checks('table', 'function')

    local id = self.id
    local ops_generator = self.ops_generator
    local client = self.client
    local fiber_obj = coroutine.create(func, id, client, ops_generator)
    if coroutine.status(fiber_obj) ~= 'dead' then
        rawset(self, 'fiber_obj', fiber_obj)
        coroutine.resume(fiber_obj)
    end

    return true
end

local function yield(self)
    dev_checks('table')

    if self.fiber_obj ~= nil and coroutine.status(self.fiber_obj) ~= 'dead' then
        coroutine.yield()
    end

    return true
end

local function terminate(self)
    dev_checks('table')

    if self.fiber_obj ~= nil and coroutine.status(self.fiber_obj) ~= 'dead' then
        --self.fiber_obj:kill() FIXME
    end

    return true
end

local function wait_completion(self)
    dev_checks('table')

    if self.fiber_obj ~= nil and coroutine.status(self.fiber_obj) ~= 'dead' then
        -- self.fiber_obj:join() FIXME
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
