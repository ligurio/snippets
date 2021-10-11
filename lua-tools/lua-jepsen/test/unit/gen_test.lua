local gen = require('jepsen.gen')
local fun = require('fun')
local fiber = require('fiber')
local clock = require('clock')

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

g.test_dump_string = function()
    t.assert_equals(gen.dump('aaa'), 'aaa')
end

g.test_dump_table = function()
    t.skip('unsupported')

    local sample = {
        a = 1,
        b = 2,
        c = 3,
        d = {
            a = 2,
            b = 3,
        }
    }
    t.assert_equals(gen.dump(sample), {})
end

g.test_gen_speed = function()
    t.skip('unsupported')

    local n = 20000
    local time_begin = clock.time()
    for _ in fun.rands(1, 2):take(n) do
        fiber.sleep(0.001)
    end
    --fiber.sleep(0.1)
    local passed_time = clock.time() - time_begin
    t.assert_ge(passed_time, 0)
    print(passed_time, time_begin)
    t.assert_ge(require('math').floor(passed_time) / n, n)
end
