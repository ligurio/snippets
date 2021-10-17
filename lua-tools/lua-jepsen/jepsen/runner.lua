local checks = require('checks')
local clock = require('clock')
local log = require('log')
local math = require('math')

local wrap = require('jepsen.client_wraps')
local pool = require('jepsen.pool')

-- Running 30s test @ 127.0.0.1:8080
--   12 threads and 400 connections
--   Thread Stats   Avg      Stdev     Max   +/- Stdev
--     Latency   635.91us    0.89ms  12.92ms   93.69%
--     Req/Sec    56.20k     8.07k   62.00k    86.54%
-- Latency Distribution
--   50% 250.00us
--   75% 491.00us
--   90% 700.00us
--   99% 5.80ms
-- Latency   635.91us    0.89ms  12.92ms   93.69%
-- Req/Sec    56.20k     8.07k   62.00k    86.54%
-- 22464657 requests in 30.00s, 17.76GB read
-- Requests/sec:    748868.53
-- Transfer/sec:    606.33MB
--
-- See also:
-- - https://github.com/wg/wrk/blob/master/src/stats.c
-- - https://github.com/wg/wrk/blob/master/scripts/report.lua
local function print_summary(total_time, nodes, ops_done)
    log.info('Running %ds test @:', total_time)
    for _, node in pairs(nodes) do
        log.info('%s', node)
    end
    if ops_done ~= nil then
        log.info('Done %d ops in time %f sec.', ops_done, total_time)
        log.info('Speed is %d ops/sec.', math.floor(ops_done / total_time))
    end
end

-- Set random seed in a code that runs test.
-- For example: math.randomseed(os.time())
local function run_test(workload, opts)
    checks(
        {
            client = 'function',
            generator = 'function',
            checker = 'function|nil',
        },
        {
            threads = 'number|nil',
            time_limit = 'number|nil',
            nodes = 'table|nil',
        }
    )

    opts.threads = opts.threads or 1

    -- Setup DB.
    local ok, err = wrap.setup(workload.client)
    if not ok then
        return err
    end

    -- Start workload.
    local total_time_begin = clock.proc()
    local p = pool.new(workload.client, workload.generator, opts)
    local ok, err = p:spawn()
    if not ok then
        return nil, err
    end

    local ok, err = p:spawn()
    if not ok then
        return nil, err
    end
    local total_passed_sec = clock.proc() - total_time_begin

    -- Teardown DB.
    ok, err = wrap.teardown(workload.client)
    if not ok then
        return err
    end

    -- Summary.
    local ops_done = 1000 -- FIXME
    print_summary(total_passed_sec, opts.nodes, ops_done)

    return true
end

return {
    run_test = run_test,
}
