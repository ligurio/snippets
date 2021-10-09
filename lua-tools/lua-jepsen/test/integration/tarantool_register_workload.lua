local checks = require('checks')
local clock = require('clock')
local errors = require('errors')
local fun = require('fun')
local math = require('math')
local net_box = require('net.box')

local ClientError = errors.new_class('ClientError', {capture_stack = false})

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

local conn
local space_name = 'register_space'

function client.open()
    checks('table')

    conn = net_box.connect('127.0.0.1:3301')
    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
end

function client.setup()
    checks('table')

    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
    conn.schema.create_space(space_name)
    conn.space.space_name:format({
        {name='id', type='number'},
        {name='value', type='string'},
    })
    conn.space.space_name:create_index('pk')
end

function client.invoke(op)
    checks('table')

    if op.f == nil or op.v == nil then
        return nil, ClientError
    end
    local ok
    if op.f == 'write' then
        ok = conn.space.space_name:replace({
            1, op.v
        })
    elseif op.f == 'read' then
        ok = conn.space.space_name:select(1)
    end

    return {
        type = ok,
        f = op.f,
        time = clock.time(),
    }
end

function client.teardown()
    checks('table')

    if conn == nil then
        return nil, ClientError
    end
    conn.space.register_space:drop()
end

function client.close()
    checks('table')

    if conn == nil then
        return nil, ClientError
    end
    conn:close()
    conn = nil
end

return {
    client = client,
    generator = fun.rands(0, 3):map(function(x)
                                        return (x == 0 and r()) or
                                               (x == 1 and w()) or
                                               (x == 2 and cas())
                                    end):take(50),
    checker = nil,
}
