local checks = require('checks')
local clock = require('clock')
local errors = require('errors')
local fun = require('fun')
local math = require('math')
local net_box = require('net.box')

local ClientError = errors.new_class('ClientError', {capture_stack = false})

math.randomseed(os.time())

--[[ Function implements a CAS (Compare And Set) operation, which takes a key,
old value, and new value and sets the key to the new value if and only if the
old value matches what's currently there, and returns a detailed response
map. If the CaS fails, it returns false.
]]
local function cas(space, tuple_id, old_value, new_value)
    local rc = false
    box.begin()
    local tuple = space:get{tuple_id}
    if tuple then
        if tuple.value == old_value then
            space:update({tuple_id}, {{'=', 2, new_value}})
            rc = true
        end
    end
    box.commit()

    return rc
end

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
local conn = net_box.connect('127.0.0.1:3301')
--assert(conn:wait_connected(0.5) == true)
--assert(conn:is_connected() == true)

local function open()
    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
end

local function setup()
    local conn = net_box.connect('127.0.0.1:3301')
    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
    --[[
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
    ]]
end

local function invoke(op)
    checks({
        f = 'string',
        v = '?'
    })

    local tuple_id = 1
    local conn = net_box.connect('127.0.0.1:3301')
    assert(conn ~= nil)
    assert(conn.space ~= nil)
    local space = conn.space[space_name]
    assert(space ~= nil)
    if op.f == 'write' then
        space:replace({tuple_id, op.v}, {timeout = 0.5})
    elseif op.f == 'read' then
        space:get({tuple_id}, {timeout = 0.5})
    elseif op.f == 'cas' then
        local old_value = op.v[1]
        local new_value = op.v[2]
        cas(space, tuple_id, old_value, new_value)
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
                               end):take(2000)
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
