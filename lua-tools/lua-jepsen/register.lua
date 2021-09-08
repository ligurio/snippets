local checks = require('checks')
local errors = require('errors')
local fiber = require('fiber')
local log = require('log')
local os = require('os')

local WorkloadError = errors.new_class('WorkloadError', {capture_stack = false})
local WorkerError = errors.new_class('WorkerError', {capture_stack = false})

local clock = require('clock')
local fun = require('fun')
local math = require('math')

math.randomseed(os.time())

local function r()
    return {
        type = 'invoke',
        f = 'read',
        v = nil,
    }
end

local function w()
    return {
        type = 'invoke',
        f = 'write',
        v = math.random(1, 10),
    }
end

local function cas()
    return {
        type = 'invoke',
        f = 'cas',
        v = {
            math.random(1, 10), -- old value
            math.random(1, 10), -- new value
        }
    }
end

local client = {}

function client.open(test)
    checks('table')

    assert(test.conn)
    --local conn = net_box.connect('127.0.0.1:3301')
    --assert(conn:ping(), true)
end

function client.setup(test)
    checks('table')

    local conn = test.conn
    assert(conn)
    conn.schema.create_space('test', {if_not_exists = true})
    conn.space.test:format({{name='id', type='number'}, {name='value', type='string'}})
    conn.space.test:create_index('primary')
end

function client.invoke(test)
    checks('table')

    local op = test.operation
    local conn = test.conn
    local space = conn.space.test
    local ok
    if op.f == 'write' then
        ok = space:replace({1, op.v})
    elseif op.f == 'read' then
        ok = space:select(1)
    end
    return {
        type = ok,
        f = op.f,
        time = clock.time(),
    }
end

function client.teardown(test)
    checks('table')

    local conn = test.conn
    local space = conn.space.test
    if space ~= nil then
        space:drop()
    end
end

function client.close(test)
    checks('table')

    --test.conn:close()
    test.conn = nil
end

local register_workload = {
    client = client,
    generator = fun.rands(0, 3):map(function(x)
                                        return (x == 0 and r()) or
                                               (x == 1 and w()) or
                                               (x == 2 and cas())
                                    end):take(50),
    checker = nil,
}

local function create_ops_channel(ch, gen)
    for _, v in gen do
        ch:put(v)
    end
end

local function run_worker(fn_client_invoke, ch)
    local op = ch:get()
    if op == nil then
        return nil, WorkerError:new('Channel is empty')
    end
    log.info('worker %s %s %d', op.type, op.f, op.v)
    local ok, err = pcall(fn_client_invoke, op)
    if err ~= nil then
        return nil, WorkerError:new('Operation failed: %s', err)
    end
    assert(ok ~= nil)
    assert(type(ok) == 'table')
    log.info('worker %s %s %d', op.type, op.f, op.v)
end

local function run_workload(w, test)
    checks({
        'table',
        'table',
        'table|nil',
        }, 'table|nil')

    assert(test.conn)
    if type(w.client.open) ~= 'function' or
       type(w.client.setup) ~= 'function' or
       type(w.client.invoke) ~= 'function' or
       type(w.client.teardown) ~= 'function' or
       type(w.client.close) ~= 'function' then
        return nil, WorkloadError:new('Wrong client interface')
    end

    local _, err = pcall(w.client.setup, test)
    if err ~= nil then
        return nil, err
    end

    local _, err = pcall(w.client.open, test)
    if err ~= nil then
        return nil, err
    end

    local ch_ops = fiber.channel()
    local fiber_ops = fiber.create(create_ops_channel, ch_ops, w.generator)
    fiber_ops:set_joinable(true)
    local _, err = pcall(run_worker, w.client.invoke, ch_ops)
    if err ~= nil then
        return nil, err
    end
    if ch_ops:empty() then
        fiber_ops:join()
        fiber_ops:cancel()
        ch_ops:close()
    end

    local _, err = pcall(w.client.close, test)
    if err ~= nil then
        return nil, err
    end

    local _, err = pcall(w.client.teardown, test)
    if err ~= nil then
        return nil, err
    end
end

local function main()
    local test = {
        conn = box,
    }
    -- temporarily defined here, to be passed from outside
    assert(type(box.cfg) == 'table')
    run_workload(register_workload, test)
    os.exit(0)
end

main()

return register_workload
