local clock = require('clock')
local fun = require('fun')
local math = require('math')

function r()
    return {
        type = 'invoke',
        f = 'read',
        v = nil,
    }
end

function w()
    return {
        type = 'invoke',
        f = 'write',
        v = math.random(1, 10),
    }
end

function cas()
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
end

function client.setup(test)
    local conn = test.conn
    assert(conn)
    conn.schema.create_space('test', {if_not_exists = true})
    conn.space.test:format({{name='id', type='number'}, {name='value', type='string'}})
    conn.space.test:create_index('primary')
end

function client.invoke(test)
    local op = test.operation
    local conn = test.conn
    local space = conn.space.test
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
    local conn = test.conn
    local space = conn.space.test
    if space ~= nil then
        space:drop()
    end
end

function client.close(test)
    test.conn = nil
end

workload = {
    client = client,
    generator = fun.rands(0, 3):map(function(x)
                                        return (x == 0 and r()) or
                                               (x == 1 and w()) or
                                               (x == 2 and cas())
                                    end):take(50),
    checker = nil,
}

return workload
