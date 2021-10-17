local clock = require('clock')
local gen = require('jepsen.gen')
local fun = require('fun')
local math = require('math')

local t = require('luatest')
local g = t.group()

g.test_iter = function()
    t.skip('Unsupported')
    t.assert_equals(gen.iter({ a = 1, b = 2, c = 3 }):take(2), nil)
end

g.test_take_while = function()
    local predicate = function(x) return x > 2 end
    -- FIXME:
    t.assert_equals(gen.take_while(predicate, fun.range(4, 8)):totable(),
                        {4, 5, 6, 7, 8})
    t.assert_equals(gen.take_n(3, fun.range(4, 10)):totable(), {4, 5, 6})
    -- TODO: check chaining
end

g.test_take_n = function()
    -- FIXME:
    t.assert_equals(gen.take_n(3, fun.range(4, 10)):totable(), {4, 5, 6})
    t.assert_equals(gen.take_n(0, fun.range(4, 10)):totable(), {})
    -- TODO: check chaining
end

g.test_take_while = function()
    local predicate = function(x) return x > 2 end
    -- FIXME:
    t.assert_equals(gen.take_while(predicate, fun.range(4, 10)):totable(),
                        {4, 5, 6, 7, 8, 9, 10})
    -- TODO: check chaining
end

g.test_iter = function()
    t.assert_equals(gen.iter({1, 2}):totable(), {1, 2})
    -- TODO: check chaining
end

g.test_range = function()
    t.assert_equals(gen.range(1, 4):totable(), {1, 2, 3, 4})
    -- TODO: check chaining
end

g.test_map = function()
    t.assert_equals(gen.range(1, 4):totable(), {1, 2, 3, 4})
end

g.test_tomap = function()
    t.assert_equals(gen.range(1, 4):totable(), {1, 2, 3, 4})
end

g.test_foldl = function()
    t.skip('Unsupported')
    t.assert_equals(gen.foldl(function(acc, x) return acc + x end, 0, gen.range(5)), 15)
end

g.test_length = function()
    t.assert_equals(gen.length({1, 2, 3, 4}), 4)
    t.assert_equals(gen.length({1, 2, nil, 4}), 4)
end

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

g.test_time_limit = function()
    t.skip('Unsupported')

    local generator = function()
        return gen.iter({ a = 1, b = 2, c = 3 }):take(5)
    end

    for _, op in generator() do
        print(op)
    end
    --t.assert_ge(130 * 1000 * 1000, op_per_sec)
end

g.test_gen_speed = function()
    t.skip('Unsupported')

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
