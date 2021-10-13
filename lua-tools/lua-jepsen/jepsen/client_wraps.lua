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

local function open(id, client)
    checks('number', 'table')

    log.info('%s Opening connection.', worker_prefix(id))
    local ok, err = pcall(client.open)
    if not ok then
        return nil, err
    end
end

local function setup(id, client)
    checks('number', 'table')

    log.info('%s Setting up DB.', worker_prefix(id))
    local ok, err = pcall(client.setup)
    if not ok then
        return nil, err
    end
end

local function start(id, client, ops_generator)
    checks('number', 'table', 'function')

    log.info('Running worker %d', id)
    local ops_done = 0 -- box.info.lsn
    for _, op in ops_generator() do
        execute_op(id, client.invoke, op)
        ops_done = ops_done + 1
    end

    return ops_done
end

local function close(id, client)
    checks('number', 'table')

    log.info('%s Closing connection', worker_prefix(id))
    local ok, err = pcall(client.close)
    if not ok then
        return nil, err
    end
end

local function teardown(id, client)
    checks('number', 'table')

    log.info('%s Tearing down DB', worker_prefix(id))
    local ok, err = pcall(client.teardown)
    if not ok then
        return nil, err
    end
end

return {
    open = open,
    setup = setup,
    start = start,
    teardown = teardown,
    close = close,
}
