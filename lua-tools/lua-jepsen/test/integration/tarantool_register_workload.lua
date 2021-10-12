local checks = require('checks')
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
        },
    }
end

local space_name = 'register_space'
local conn = net_box.connect('127.0.0.1:3301')

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
    assert(conn:wait_connected(0.5) == true)
    assert(conn:is_connected() == true)

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
        v = '?',
    })

    local tuple_id = 1
    local conn = net_box.connect('127.0.0.1:3301')
    local space = conn.space[space_name]
    assert(space ~= nil)
    local cur_value = op.v
    local state = false
    if op.f == 'write' then
        cur_value = space:replace({tuple_id, op.v}, {timeout = 0.05})
        cur_value = cur_value.value
        state = true
    elseif op.f == 'read' then
        cur_value = space:get(tuple_id, {timeout = 0.05})
        if cur_value ~= nil then
            cur_value = cur_value.value
        end
        state = true
    elseif op.f == 'cas' then
        local old_value = op.v[1]
        local new_value = op.v[2]
        cur_value, state = conn:call('cas', {
            space_name,
            tuple_id,
            old_value,
            new_value
        }, {timeout = 0.5})
    else
        -- Unknown operation.
        return nil, ClientError
    end

    return {
        v = cur_value,
        f = op.f,
        state = state,
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
