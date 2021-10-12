local checks = require('checks')
local clock = require('clock')
local inspect = require('inspect')
local log = require('log')
local math = require('math')

local function op_to_string(op)
    checks({
            f = 'string',
            v = '?',
            state = 'nil|boolean',
        }
    )

    local state = op.state
    if state == true then
        state = 'ok'
    elseif state == false then
        state = 'fail'
    else
        state = 'invoke'
    end
    local str = string.format('%-10s %-10s %-10s', state, op.f, inspect.inspect(op.v))

    return str
end

local function execute_op(func, op)
    log.info('[jepsen worker] %s', op_to_string(op))
    local ok, res = pcall(func, op)
    if not ok then
        log.info(res)
    else
        assert(res.state ~= nil)
        assert(res.f ~= nil)
        log.info('[jepsen worker] %s',  op_to_string(res))
    end
end

-- 3  :ok     :transfer   {:from 8, :to 2, :amount 3}
-- 0  :ok     :transfer   {:from 1, :to 9, :amount 1}
-- 0  :invoke :transfer   {:from 3, :to 9, :amount 5}
-- 4  :ok     :read       {0 5, 1 10, 2 12, 3 10, 4 11, 5 5, 6 20, 7 0, 8 10, 9 17}
-- 4  :invoke :read       nil
-- 3  :ok     :read       {0 5, 1 9, 2 12, 3 10, 4 11, 5 5, 6 20, 7 0, 8 10, 9 18}
-- 3  :invoke :read       nil
--
-- state can be nil (invoke), true (ok) or false (fail)
-- f is defined by user
-- v is defined by user
local function start_worker(invoke_func, ops_generator)
    checks('function', 'function')

    local ops_done = 0 -- box.info.lsn
    local total_time_begin = clock.proc()
    for _, op in ops_generator() do
        execute_op(invoke_func, op)
        ops_done = ops_done + 1
    end

    local total_passed_sec = clock.proc() - total_time_begin
    log.info('Done %d ops in time %f sec.', ops_done, total_passed_sec)
    log.info('Speed is %d ops/sec.', math.floor(ops_done / total_passed_sec))
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
