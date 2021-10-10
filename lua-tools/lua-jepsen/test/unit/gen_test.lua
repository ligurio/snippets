local gen = require('jepsen.gen')

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
