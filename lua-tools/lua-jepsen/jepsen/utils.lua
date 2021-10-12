local checks = require('checks')
local inspect = require('inspect')

local function op_to_string(op)
    checks({
            f = 'string',
            v = '?',
            state = 'nil|boolean',
        }
    )

    local state = op.state
    if state == true then
        state = 'ok'
    elseif state == false then
        state = 'fail'
    else
        state = 'invoke'
    end
    local str = string.format('%-10s %-10s %-10s', state, op.f, inspect.inspect(op.v))

    return str
end

return {
    op_to_string = op_to_string,
}
