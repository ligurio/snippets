local dev_checks = require('jepsen.dev_checks')
local log = require('jepsen.log')
local utils = require('jepsen.utils')

local function setup(client, addr)
    dev_checks('function', 'string')

    local c = client(addr)
    local ok, err = pcall(c.open, c)
    if not ok then
        return nil, err
    end

    log.info('Setting up DB on %s', addr)
    ok, err = pcall(c.setup, c)
    if not ok then
        return nil, err
    end

    ok, err = pcall(c.close, c)
    if not ok then
        return nil, err
    end

    return true
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
--
local function start(id, client, ops_generator)
    dev_checks('number', 'function', 'function')

    local addr = '127.0.0.1:3301' -- FIXME
    local c = client(addr)
    local ok, err = pcall(c.open, c)
    if not ok then
        return nil, err
    end

    local ops_done = 0 -- box.info.lsn
    for _, op in ops_generator() do
        assert(type(op.f) == 'string')
        log.info('[%d] %s', id, utils.op_to_string(op))
        local ok, res = pcall(c.invoke, c, op)
        if not ok then
            log.info(res)
        else
            assert(res.state ~= nil)
            assert(res.f ~= nil)
            log.info('[%d] %-50s', id, utils.op_to_string(res))
        end
        ops_done = ops_done + 1
    end

    return ops_done
end

local function teardown(client, addr)
    dev_checks('function', 'string')

    local c = client(addr)
    local ok, err = pcall(c.open, c)
    if not ok then
        return nil, err
    end

    log.info('Tearing down DB on %s', addr)
    ok, err = pcall(c.teardown, c)
    if not ok then
        return nil, err
    end

    ok, err = pcall(c.close, c)
    if not ok then
        return nil, err
    end

    return true
end

return {
    setup = setup,
    start = start,
    teardown = teardown,
}
