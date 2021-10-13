-- Pool creates a specified number of workers, start them and stop.

local checks = require('checks')

local worker = require('jepsen.worker_fiber')
local wrap = require('jepsen.client_wraps')

-- Starts a fiber that reads a generator and put operations to a shared
-- channel, starts a number of fibers that read operations from a channel and
-- execute them.
local function _start(invoke_func, ops_generator)
    checks('function', 'function')

    local ok, err = pcall(worker.start, invoke_func, ops_generator)
    if not ok then
        return nil, err
    end
end

local function wait_completion(self)
    local pool = rawget(self, 'pool')
    if pool == box.NULL then
        return
    end
    local opts = rawget(self, 'opts')
    for i = 1, opts.threads do
        pool[i]:wait_completion()
        pool[i]:yield()
    end
end

local function execute(self, func)
    local opts = rawget(self, 'opts')
    local pool = rawget(self, 'pool')
    for i = 1, opts.threads do
        pool[i]:create(func)
        pool[i]:yield()
    end

    self.wait_completion(self)
end

local function terminate(self)
    local opts = rawget(self, 'opts')
    local pool = rawget(self, 'pool')
    for i = 1, opts.threads do
        pool[i]:terminate()
    end
end

local function run(self)
    -- FIXME: check return code
    self.execute(self, wrap.open)
    self.execute(self, wrap.setup)
    self.execute(self, wrap.start)
    self.execute(self, wrap.teardown)
    self.execute(self, wrap.close)
end

local mt = {
    __type = 'Workload',
    __newindex = function()
        error('Workload object is immutable.', 2)
    end,
    __index = {
        terminate = terminate,
        wait_completion = wait_completion,
        execute = execute,
        run = run,
    },
}

local function new(client, generator, opts)
    checks('table', 'function', 'table')

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
    start = _start,
    new = new,
}
