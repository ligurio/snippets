local checks = require('checks')
local log = require('log')
local os = require('os')

local utils = require('jepsen.utils')

local function prefix_str(id)
    checks('number')

    return string.format('%s [%d]', os.date("%m/%d/%Y %H:%M:%S"), id)
end

local function setup(client, addr)
    checks('function', 'string')

    local c = client()
    local ok, err = pcall(c.open, c, addr)
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

local function start(id, client, ops_generator)
    checks('number', 'function', 'function')

    local c = client()
    local ok, err = pcall(c.open, c)
    if not ok then
        return nil, err
    end

    local ops_done = 0 -- box.info.lsn
    for _, op in ops_generator() do
        assert(type(op.f) == 'string')
        log.info('%s %s', prefix_str(id), utils.op_to_string(op))
        local ok, res = pcall(c.invoke, c, op)
        if not ok then
            log.info(res)
        else
            assert(res.state ~= nil)
            assert(res.f ~= nil)
            log.info('%s %-50s', prefix_str(id), utils.op_to_string(res))
        end
        ops_done = ops_done + 1
    end

    return ops_done
end

local function teardown(client, addr)
    checks('function', 'string')

    local c = client()
    local ok, err = pcall(c.open, c, addr)
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
