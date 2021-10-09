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
