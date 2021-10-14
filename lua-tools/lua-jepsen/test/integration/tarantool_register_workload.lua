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
            math.random(1, 10), -- Old value.
            math.random(1, 10), -- New value.
        },
    }
end

local addr = '127.0.0.1:3301'
local space_name = 'register_space'
local conn = net_box.connect(addr)

local function open()
    if not conn or conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
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
    if not conn or conn:ping() ~= true then
        return nil, ClientError
    end
    assert(conn:is_connected() == true)

    local space = conn.space[space_name]
    assert(space ~= nil)
    local tuple_value
    local state
    if op.f == 'write' then
        tuple_value = space:replace({tuple_id, op.v}, {timeout = 0.05})
        tuple_value = tuple_value.value
        state = true
    elseif op.f == 'read' then
        tuple_value = space:get(tuple_id, {timeout = 0.05})
        if tuple_value ~= nil then
            tuple_value = tuple_value.value
        end
        state = true
    elseif op.f == 'cas' then
        local old_value = op.v[1]
        local new_value = op.v[2]
        tuple_value, state = conn:call('cas', {
            space_name,
            tuple_id,
            old_value,
            new_value
        }, {timeout = 0.5})
    else
        return nil, ClientError:new('Unknown operation (%s)', op.f)
    end

    return {
        v = tuple_value,
        f = op.f,
        state = state,
    }
end

local function teardown()
    local conn = net_box.connect(addr)
    if conn == nil then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    -- FIXME: conn.space.register_space:drop()
end

local function close()
    local conn = net_box.connect(addr)
    if conn == nil then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    conn:close()
end

local function generator()
    local n = 5000
    return fun.rands(0, 3):map(function(x)
                                   return (x == 0 and r()) or
                                          (x == 1 and w()) or
                                          (x == 2 and cas())
                               end):take(n)
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
