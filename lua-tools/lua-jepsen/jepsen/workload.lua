local checks = require('checks')

local worker = require('jepsen.worker')

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

return {
    start_workload = start_workload,
}
