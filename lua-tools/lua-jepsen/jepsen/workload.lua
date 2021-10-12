local checks = require('checks')

local worker = require('jepsen.worker_fiber')

-- Starts a fiber that reads a generator and put operations to a shared
-- channel, starts a number of fibers that read operations from a channel and
-- execute them.
local function start_workload(invoke_func, ops_generator)
    checks('function', 'function')

    local ok, err = pcall(worker.start_worker, invoke_func, ops_generator)
    if not ok then
        return nil, err
    end
end

local function start()
end

local function stop()
end

local mt = {
    __type = 'Workload',
    __newindex = function()
        error('Workload object is immutable.', 2)
    end,
    __index = {
        start = start,
        stop = stop,
    },
}

local function new(client, opts)
    return setmetatable({
        client = client,
        opts = opts,
        --pool = pool,
    }, mt)
end

return {
    start_workload = start_workload,
    new = new,
}
