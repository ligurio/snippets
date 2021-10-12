--[[
-- Jepsen generators http://jepsen-io.github.io/jepsen/jepsen.generator.html
-- Lua stateless iterators https://www.lua.org/pil/7.3.html
--]]

local fun = require('fun')
local fiber = require('fiber')
local checks = require('checks')

local function dump(o)
    checks('table|string')

    if type(o) == 'string' then
        return tostring(o)
    end

    local s = '{ '
    for k, v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
    end

    return s .. '} '
end

local return_if_not_empty = function(state_x, ...)
    if state_x == nil then
        return nil
    end
    return ...
end

local function proxy(gen_x, param_x, state_x)
    checks('table', 'table', 'table')

    return return_if_not_empty(gen_x(param_x, state_x))
end

local function stagger(time, gen_x, param_x, state_x)
    checks('number', 'table', 'table', 'table')

    fiber.sleep(time)

    return proxy(gen_x, param_x, state_x)
end

-- mix({
--    r,
--    w,
--    cas
-- })
local function mix()
end

local function cycle(table)
    checks('table')

    return fun.iter(table)
end

local function chain()
    -- https://luafun.github.io/compositions.html#fun.chain
end

local function take()
    -- https://luafun.github.io/slicing.html#fun.take
end

local function take_while()
    -- https://luafun.github.io/slicing.html#fun.take_while
end

local function filter()
    -- https://luafun.github.io/filtering.html#fun.filter
end

local function map()
    -- https://luafun.github.io/transformations.html#fun.map
end

return {
    chain = chain,
    cycle = cycle,
    dump = dump,
    filter = filter,
    map = map,
    mix = mix,
    stagger = stagger,
    take = take,
    take_while = take_while,
}
