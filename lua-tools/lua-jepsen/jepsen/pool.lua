-- Pool creates a specified number of workers, start them and stop.

local checks = require('checks')

local worker = require('jepsen.worker_fiber')
local wrap = require('jepsen.client_wraps')

local function wait_completion(self)
    checks('table')

    for i = 1, self.opts.threads do
        self.pool[i]:wait_completion()
    end

    return true
end

local function terminate(self)
    checks('table')

    for i = 1, self.opts.threads do
        self.pool[i]:terminate()
    end

    return true
end

local function spawn(self)
    checks('table')

    for i = 1, self.opts.threads do
        local ok, err = self.pool[i]:spawn(wrap.start)
        if not ok then
            return nil, err
        end
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
    checks('function', 'function', 'table')

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
