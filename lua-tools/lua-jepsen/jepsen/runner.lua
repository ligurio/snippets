local checks = require('checks')
local clock = require('clock')
local log = require('log')
--local math = require('math')

local wrap = require('jepsen.client_wraps')
local pool = require('jepsen.pool')

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

    opts.threads = opts.threads or 1

    -- Setup DB.
    local ok, err = wrap.setup(workload.client.setup, opts)
    if not ok then
        return err
    end

    -- Start workload.
    local total_time_begin = clock.proc()
    local p = pool.new(workload.client, workload.generator, opts)
    assert(p ~= nil)
    local ok, err = p:run()
    if not ok then
        return nil, err
    end
    local total_passed_sec = clock.proc() - total_time_begin

    -- Teardown DB.
    ok, err = wrap.teardown(workload.client.teardown, opts)
    if not ok then
        return err
    end

    local ops_done = 1000 -- FIXME
    if ops_done ~= nil then
        log.info('Done %d ops in time %f sec.', ops_done, total_passed_sec)
        log.info('Speed is %d ops/sec.', math.floor(ops_done / total_passed_sec))
    end
end

return {
    run_test = run_test,
}
