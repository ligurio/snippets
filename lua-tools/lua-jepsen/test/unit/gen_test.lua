local clock = require('clock')
local gen = require('jepsen.gen')
local math = require('math')

local t = require('luatest')
local g = t.group()

g.test_mix = function()
    t.skip('Unsupported')
    local gen, param, state = gen.mix(
        gen.duplicate('a'),
        gen.duplicate('b'),
        gen.duplicate('c')
        --{1, 2, 3},
        --{4, 4, 4},
        --{5, 5, 5}

    ):take(4)

    for _, op in gen, param, state do
        print(op)
        --t.assert(op.f == 'read' or op.f == 'write')
    end
end

g.test_duplicate = function()
    local gen, param, state = gen.duplicate('a'):take(3)
    for _, op in gen, param, state do
        print(op)
        --t.assert(op.f == 'read' or op.f == 'write')
    end
end

g.test_time_limit = function()
    local generator = function()
        return gen.iter({ a = 1, b = 2, c = 3 }):take(5)
    end

    for _, op in generator() do
        print(op)
    end
    --t.assert_ge(130 * 1000 * 1000, op_per_sec)
end

g.test_gen_speed = function()
    local n = 2 * 1000 * 1000
    local function generator()
        return gen.rands(0, 3):map(function(x)
                                       return (x == 0 and {1}) or
                                              (x == 1 and {2}) or
                                              (x == 2 and {3})
                                   end):take(n)
    end
    local time_begin = clock.monotonic()
    for _ in generator() do
        -- Empty.
    end
    local passed_sec = clock.monotonic() - time_begin
    local op_per_sec = math.floor(n / passed_sec)

    t.assert_ge(130 * 1000 * 1000, op_per_sec)
end
