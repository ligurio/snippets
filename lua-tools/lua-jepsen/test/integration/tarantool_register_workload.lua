local checks = require('checks')
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

return register_workload
