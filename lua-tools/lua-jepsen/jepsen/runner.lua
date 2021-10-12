local checks = require('checks')
local clock = require('clock')
local log = require('log')
local math = require('math')

local workload_lib = require('jepsen.workload')

local function run_test(workload, opts)
    checks(
        {
            client = {
                open = 'function',
                setup = 'function',
                invoke = 'function',
                teardown = 'function',
                close = 'function'
            },
            generator = 'function',
            checker = 'function|nil',
        },
        {
            threads = 'number|nil',
            time_limit = 'number|nil',
            nodes = 'table|nil',
        }
    )

    local client = workload.client
    log.info('Open a connection.')
    local ok, err = pcall(client.open, opts)
    if not ok then
        return nil, err
    end

    log.info('Setup a client.')
    ok, err = pcall(client.setup, opts)
    if not ok then
        return nil, err
    end

    log.info('Start a workload.')
    local total_time_begin = clock.proc()
    ok, err = workload_lib.start_workload(client.invoke, workload.generator, opts)
    if not ok then
        return nil, err
    end
    local total_passed_sec = clock.proc() - total_time_begin
    local ops_done = 1000 -- FIXME
    if ops_done then
        log.info('Done %d ops in time %f sec.', ops_done, total_passed_sec)
        log.info('Speed is %d ops/sec.', math.floor(ops_done / total_passed_sec))
    end

    log.info('Close a client.')
    ok, err = pcall(client.close, opts)
    if not ok then
        return nil, err
    end

    log.info('Teardown a client.')
    ok, err = pcall(client.teardown, opts)
    if not ok then
        return nil, err
    end
end

return {
    run_test = run_test,
}
