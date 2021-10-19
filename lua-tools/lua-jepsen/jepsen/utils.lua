local inspect = require('inspect')

local dev_checks = require('jepsen.dev_checks')

local function decode_op_state(state)
    dev_checks('?boolean')

    local state_type = {
        [true] = 'ok',
        [false] = 'fail',
    }

    return state_type[state] or 'invoke'
end

local function op_to_string(op)
    dev_checks({
            f = 'string',
            v = '?',
            state = 'nil|boolean',
        }
    )

    return string.format('%-10s %-10s %-10s', decode_op_state(op.state),
                                              op.f,
                                              inspect.inspect(op.v))
end

return {
    op_to_string = op_to_string,
}
