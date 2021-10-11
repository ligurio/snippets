local math = require('math')
local clock = require('clock')
local checks = require('checks')
local log = require('log')
local inspect = require('inspect')

-- [jepsen worker 3] jepsen.util: 3  :ok     :transfer       {:from 8, :to 2, :amount 3}
-- [jepsen worker 0] jepsen.util: 0  :ok     :transfer       {:from 1, :to 9, :amount 1}
-- [jepsen worker 0] jepsen.util: 0  :invoke :transfer       {:from 3, :to 9, :amount 5}
-- [jepsen worker 4] jepsen.util: 4  :ok     :read   {0 5, 1 10, 2 12, 3 10, 4 11, 5 5, 6 20, 7 0, 8 10, 9 17}
-- [jepsen worker 4] jepsen.util: 4  :invoke :read   nil
-- [jepsen worker 3] jepsen.util: 3  :ok     :read   {0 5, 1 9, 2 12, 3 10, 4 11, 5 5, 6 20, 7 0, 8 10, 9 18}
-- [jepsen worker 3] jepsen.util: 3  :invoke :read   nil
local function start_worker(fn_invoke_op, op_generator)
    checks('function', 'function')

    local ops_done = 0 -- box.info.lsn
    local time_begin = clock.proc()
    for _, op in op_generator() do
        log.info('[jepsen worker] :invoke   :%s      :%s', op.f, inspect.inspect(op.v))
        local ok, err = pcall(fn_invoke_op, op)
        if not ok then
            log.info(err)
        else
            ops_done = ops_done + 1
            log.info('[jepsen worker] :ok       :%s      :%s', op.f, inspect.inspect(op.v))
        end
    end
    local passed_sec = clock.proc() - time_begin
    log.info('Done %d ops in time %f sec.', ops_done, passed_sec)
    log.info('Speed is %d ops/sec.', math.floor(ops_done / passed_sec))
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
            generator = 'function',
            checker = 'table|nil',
        },
        {
            threads = 'number|nil',
            time_limit = 'number|nil',
            nodes = 'table|nil',
        }
    )

    local client = workload.client
    log.info('Open a connection.')
    local ok, err = pcall(client.open, test)
    if not ok then
        return nil, err
    end

    log.info('Setup a client.')
    ok, err = pcall(client.setup, test)
    if not ok then
        return nil, err
    end

    log.info('Start a worker.')
    ok, err = pcall(start_worker, client.invoke, workload.generator)
    if not ok then
        return nil, err
    end

    log.info('Close a client.')
    ok, err = pcall(client.close, test)
    if not ok then
        return nil, err
    end

    log.info('Teardown a client.')
    ok, err = pcall(client.teardown, test)
    if not ok then
        return nil, err
    end
end

return {
    run_test = run_test,
}
