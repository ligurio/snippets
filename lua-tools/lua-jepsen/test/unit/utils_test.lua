local utils = require('jepsen.utils')

local t = require('luatest')
local g = t.group()

g.test_op_to_string_state_nil = function()
    local op = {
        f = 'read',
        v = 10,
        state = nil,
    }

    local str = utils.op_to_string(op)
    t.assert_equals(str, 'invoke     read       10        ')
end

g.test_op_to_string_state_true = function()
    local op = {
        f = 'read',
        v = 10,
        state = true,
    }

    local str = utils.op_to_string(op)
    t.assert_equals(str, 'ok         read       10        ')
end

g.test_op_to_string_state_false = function()
    local op = {
        f = 'read',
        v = 10,
        state = false,
    }

    local str = utils.op_to_string(op)
    t.assert_equals(str, 'fail       read       10        ')
end
