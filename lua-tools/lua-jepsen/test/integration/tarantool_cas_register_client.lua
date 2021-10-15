local checks = require('checks')
local errors = require('errors')
local math = require('math')
local net_box = require('net.box')

local ClientError = errors.new_class('ClientError', {capture_stack = false})

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

local space_name = 'register_space'
local addr = '127.0.0.1:3301' -- FIXME

local function open(self)
    checks('table')

    local conn = net_box.connect(addr)
    rawset(self, 'conn', conn)
    if conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
    end

    return true
end

local function setup(self)
    checks('table')

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
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

    return true
end

local function invoke(self, op)
    checks('table', {
        f = 'string',
        v = '?',
    })

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError
    end

    local tuple_id = 1
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

local function teardown(self)
    checks('table')

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    -- FIXME: conn.space.register_space:drop()

    return true
end

local function close(self)
    checks('table')

    local conn = rawget(self, 'conn')
    if conn:ping() ~= true then
        return nil, ClientError:new('Failed connect to %s', addr)
    end
    conn:close()

    return true
end

local client_mt = {
    __tostring = '<client>';
    __index = {
        open = open,
        setup = setup,
        invoke = invoke,
        teardown = teardown,
        close = close,
    },
    __newindex = function()
        error('Client object is immutable.', 2)
    end
}

local function new()
    return setmetatable({
        conn = box.NULL,
    }, client_mt)
end

return {
    new = new,
    ops = {
       r = r,
       w = w,
       cas = cas,
    }
}
