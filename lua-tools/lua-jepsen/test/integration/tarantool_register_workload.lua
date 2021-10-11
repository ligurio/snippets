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
        f = 'read',
        v = nil,
    }
end

local function w()
    return {
        f = 'write',
        v = math.random(1, 10),
    }
end

local function cas()
    return {
        f = 'cas',
        v = {
            math.random(1, 10), -- old value
            math.random(1, 10), -- new value
        }
    }
end

local space_name = 'register_space'

local function open()
    local conn = net_box.connect('127.0.0.1:3301')
    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
end

local function setup()
    local conn = net_box.connect('127.0.0.1:3301')
    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
    conn.schema.create_space(space_name)
    conn.space.space_name:format({
        {
            name='id', type='number'
        },
        {
            name='value', type='string'
        },
    })
    conn.space.space_name:create_index('pk')
end

local function invoke(op)
    checks({
        f = 'string',
        v = '?'
    })

    local conn = net_box.connect('127.0.0.1:3301')
    if op.f == 'write' then
        --[[
        conn.space.space_name:insert({
            1, op.v
        })
        ]]
    elseif op.f == 'read' then
        conn.space.space_name:get(1)
    elseif op.f == 'cas' then
        -- TODO
    end

    return {
        f = op.f,
        time = clock.time(),
    }
end

local function teardown()
    local conn = net_box.connect('127.0.0.1:3301')
    if conn == nil then
        return nil, ClientError
    end
    -- FIXME: conn.space.register_space:drop()
end

local function close()
    local conn = net_box.connect('127.0.0.1:3301')
    if conn == nil then
        return nil, ClientError
    end
    conn:close()
end

local function generator()
    return fun.rands(0, 3):map(function(x)
                                return (x == 0 and r()) or
                                       (x == 1 and w()) or
                                       (x == 2 and cas())
                               end):take(50)
end

return {
    client = {
        open = open,
        setup = setup,
        invoke = invoke,
        teardown = teardown,
        close = close,
    },
    generator = generator,
    checker = nil,
}
