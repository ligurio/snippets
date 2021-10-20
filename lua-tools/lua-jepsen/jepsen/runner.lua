local checks = require('checks')
local clock = require('clock')
local math = require('math')

local log = require('jepsen.log')
local pool = require('jepsen.pool')
local wrapper = require('jepsen.client_wrappers')

-- checks...............: 100.00% 34467         0
-- data_received........: 0 B     0 B/s
-- data_sent............: 0 B     0 B/s
-- iteration_duration...: avg=143.57µs min=0s med=0s max=43.24ms p(90)=519.2µs p(95)=985.47µs
-- iterations...........: 34467   6812.032587/s
-- https://k6.io/blog/load-testing-sql-databases-with-k6/
--
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
-- - https://github.com/libmoon/libmoon/blob/master/lua/histogram.lua
local function print_summary(total_time, ops_done, opts)
    checks('number', 'number', 'table')

    log.info('Running test %.3fs with %d thread(s) @:', total_time, opts.threads)
    for _, addr in pairs(opts.nodes) do
        log.info('%s', addr)
    end
    if ops_done ~= nil then
        local rps = math.floor(ops_done / total_time)
        log.info('Total requests: %12d', ops_done)
        log.info('Requests/sec: %15d', rps)
        log.info('Requests with errors:') -- FIXME
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
    for _, addr in pairs(opts.nodes) do
        local ok, err = wrapper.setup(workload.client, addr)
        if not ok then
            return nil, err
        end
    end

    -- Start workload.
    local total_time_begin = clock.proc()
    local p = pool.new(workload.client, workload.generator, opts)
    local ok, err = p:spawn()
    if not ok then
        return nil, err
    end
    local total_passed_sec = clock.proc() - total_time_begin

    -- Teardown DB.
    for _, addr in pairs(opts.nodes) do
        local ok, err = wrapper.teardown(workload.client, addr)
        if not ok then
            return nil, err
        end
    end

    -- Summary.
    local ops_done = 1000 -- FIXME
    print_summary(total_passed_sec, ops_done, opts)

    return true
end

return {
    run_test = run_test,
}
