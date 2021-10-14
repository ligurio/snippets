local gen = require('jepsen.gen')
local fun = require('fun')
local fiber = require('fiber')
local clock = require('clock')
local math = require('math')

local t = require('luatest')
local g = t.group()

g.test_cycle = function()
    gen.cycle({1, 2, 3})
end

g.test_mix_tables = function()
    t.skip('unsupported')

    local r = { f = 'read' }
    local w = { f = 'write' }
    for _, op in gen.mix({r, w}):take(4) do
        t.assert(op.f == 'read' or op.f == 'write')
    end
end

g.test_mix_functions = function()
    t.skip('unsupported')

    local function r() return { f = 'read' } end
    local function w() return { f = 'write' } end
    for _, op in gen.mix({r, w}):take(4) do
        t.assert(op.f == 'read' or op.f == 'write')
    end
end

g.test_gen_speed = function()
    local n = 2 * 1000 * 1000
    local function generator()
        return fun.rands(0, 3):map(function(x)
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
