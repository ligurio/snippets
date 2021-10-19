-- Pool creates a specified number of workers, start them and stop.

local dev_checks = require('jepsen.dev_checks')
local wrapper = require('jepsen.client_wrappers')

local worker_fiber = require('jepsen.worker_fiber')
local worker_coroutine = require('jepsen.worker_coroutine')

local function wait_completion(self)
    dev_checks('table')

    for i = 1, self.opts.threads do
        self.pool[i]:wait_completion()
    end

    return true
end

local function terminate(self)
    dev_checks('table')

    for i = 1, self.opts.threads do
        self.pool[i]:terminate()
    end

    return true
end

local function spawn(self)
    dev_checks('table')

    for i = 1, self.opts.threads do
        local ok, err = self.pool[i]:spawn(wrapper.start)
        if not ok then
            return nil, err
        end
        self.pool[i]:yield()
    end
    self:wait_completion()

    return true
end

local mt = {
    __type = '<pool>',
    __tostring = function(self)
        return '<pool>'
    end,
    __newindex = function()
        error('Workload object is immutable.', 2)
    end,
    __index = {
        terminate = terminate,
        wait_completion = wait_completion,
        spawn = spawn,
    },
}

local function new(client, generator, opts)
    dev_checks('function', 'function', 'table')

    local worker = worker_fiber
    --local worker = worker_coroutine

    local pool = {}
    for i = 1, opts.threads do
        pool[i] = worker.new(i, client, generator)
    end

    return setmetatable({
        client = client,
        generator = generator,
        opts = opts,
        pool = pool,
    }, mt)
end

return {
    new = new,
}
