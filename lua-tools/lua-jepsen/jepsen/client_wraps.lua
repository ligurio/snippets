local checks = require('checks')
local log = require('log')
local os = require('os')

local utils = require('jepsen.utils')

local function worker_prefix(id)
    checks('number')

    return string.format('%s [%d]', os.date("%m/%d/%Y %H:%M:%S"), id)
end

local function execute_op(id, func, op)
    checks('number', 'function', {
        f = 'string',
        v = '?'
    })
    log.info('%s %s', worker_prefix(id), utils.op_to_string(op))
    local ok, res = pcall(func, op)
    if not ok then
        log.info(res)
    else
        assert(res.state ~= nil)
        assert(res.f ~= nil)
        log.info('%s %s', worker_prefix(id), utils.op_to_string(res))
    end
end

-- FIXME: Run setup on each node.
local function setup(client_setup_func)
    checks('function')

    log.info('Setting up DB')
    local ok, err = pcall(client_setup_func)
    if not ok then
        return nil, err
    end

    return true
end

local function open(id, client)
    checks('number', 'table')

    log.info('%s Opening a connection', worker_prefix(id))
    local ok, err = pcall(client.open)
    if not ok then
        return nil, err
    end

    return true
end

local function start(id, client, ops_generator)
    checks('number', 'table', 'function')

    local ops_done = 0 -- box.info.lsn
    for _, op in ops_generator() do
        execute_op(id, client.invoke, op)
        ops_done = ops_done + 1
    end

    return ops_done
end

local function close(id, client)
    checks('number', 'table')

    log.info('%s Closing a connection', worker_prefix(id))
    local ok, err = pcall(client.close)
    if not ok then
        return nil, err
    end

    return true
end

-- FIXME: Run teardown on each node.
local function teardown(client_teardown_func)
    checks('function')

    log.info('Tearing down DB')
    local ok, err = pcall(client_teardown_func)
    if not ok then
        return nil, err
    end

    return true
end

return {
    open = open,
    setup = setup,
    start = start,
    teardown = teardown,
    close = close,
}
