-- Pool creates a specified number of workers, start them and stop.

local checks = require('checks')

local worker = require('jepsen.worker_fiber')
local wrap = require('jepsen.client_wraps')

local function wait_completion(self)
    checks('table')

    local pool = rawget(self, 'pool')
    local opts = rawget(self, 'opts')
    for i = 1, opts.threads do
        pool[i]:wait_completion()
        pool[i]:yield()
    end

    return true
end

local function execute(pool, opts)
    checks('table', 'table')

    for i = 1, opts.threads do
        pool[i]:create(wrap.start)
        pool[i]:yield()
    end

    return true
end

local function terminate(self)
    checks('table')

    local opts = rawget(self, 'opts')
    local pool = rawget(self, 'pool')
    for i = 1, opts.threads do
        pool[i]:terminate()
    end

    return true
end

local function run(self)
    checks('table')

    local opts = rawget(self, 'opts')
    local pool = rawget(self, 'pool')
    local ok, err = execute(pool, opts)
    if not ok then
        return nil, err
    end

    ok, err = self:wait_completion()
    if not ok then
        return nil, err
    end
end

local mt = {
    __type = '<pool>',
    __newindex = function()
        error('Workload object is immutable.', 2)
    end,
    __index = {
        terminate = terminate,
        wait_completion = wait_completion,
        run = run,
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
