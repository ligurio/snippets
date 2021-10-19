local dev_checks = require('checks')
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

local function open(self)
    dev_checks('table')

    local conn = net_box.connect(self.addr)
    if conn:ping() ~= true then
        return nil, ClientError:new('No connection to %s', self.addr)
    end
    assert(conn:wait_connected(0.5) == true)
    assert(conn:is_connected() == true)
    rawset(self, 'conn', conn)

    return true
end

local function setup(self)
    dev_checks('table')

    if self.conn:ping() ~= true then
        return nil, ClientError:new('No connection to %s', self.addr)
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

    return true
end

local function invoke(self, op)
    dev_checks('table', {
        f = 'string',
        v = '?',
    })

    if self.conn:ping() ~= true then
        return nil, ClientError:new('No connection to %s', self.addr)
    end

    local tuple_id = 1
    local space = self.conn.space[space_name]
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
        tuple_value, state = self.conn:call('cas', {
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
    dev_checks('table')

    if self.conn:ping() ~= true then
        return nil, ClientError:new('No connection to %s', self.addr)
    end
    -- FIXME: conn.space.register_space:drop()

    return true
end

local function close(self)
    dev_checks('table')

    if self.conn:ping() == true then
        self.conn:close()
    end

    return true
end

local client_mt = {
    __type = '<client>',
    __tostring = function(self)
        return '<client>'
    end,
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

local function new(addr)
    dev_checks('string')

    return setmetatable({
        addr = addr,
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
