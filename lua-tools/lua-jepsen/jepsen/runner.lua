local checks = require('checks')
--local errors = require('errors')
local log = require('log')

--local WorkloadError = errors.new_class('WorkloadError', {capture_stack = false})
--local WorkerError = errors.new_class('WorkerError', {capture_stack = false})

local function start_worker(invoke_fn, op_generator)
    checks('function', 'table')

    for i, a, b in ipairs(op_generator) do
        print(i, a, b)
        pcall(invoke_fn, a)
    end
end

local function run_test(workload, test)
    checks(
        {
            client = {
                open = 'function',
                setup = 'function',
                invoke = 'function',
                teardown = 'function',
                close = 'function'
            },
            generator = 'table',
            checker = 'table|nil',
        },
        {
            concurrency = 'number|nil',
            time_limit = 'number|nil',
            nodes = 'table|nil',
        }
    )

    local client = workload.client
    log.info('Open a connection')
    local _, err = pcall(client.open, test)
    if err ~= nil then
        return nil, err
    end

    log.info('Setup a client')
    _, err = pcall(client.setup, test)
    if err ~= nil then
        return nil, err
    end

    log.info('Start a worker')
    _, err = pcall(start_worker, client.invoke, workload.generator)
    if err ~= nil then
        return nil, err
    end

    log.info('Close a client')
    _, err = pcall(client.close, test)
    if err ~= nil then
        return nil, err
    end

    log.info('Teardown a client')
    _, err = pcall(client.teardown, test)
    if err ~= nil then
        return nil, err
    end
end

return {
    run_test = run_test,
}
