--[[
-- Jepsen generators http://jepsen-io.github.io/jepsen/jepsen.generator.html
-- Lua stateless iterators https://www.lua.org/pil/7.3.html
--]]

local fun = require('fun')
local fiber = require('fiber')
local checks = require('checks')
local inspect = require('inspect')
local errors = require('errors')

local GeneratorError = errors.new_class('GeneratorError', {capture_stack = false})

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

local wrap = function(gen, param, state)
    return setmetatable({
        gen = gen,
        param = param,
        state = state
    }, iterator_mt), param, state
end

local rawiter = function(obj, param, state)
    assert(obj ~= nil, "invalid iterator")
    if type(obj) == "table" then
        local mt = getmetatable(obj);
        if mt ~= nil then
            if mt == iterator_mt then
                return obj.gen, obj.param, obj.state
            elseif mt.__ipairs ~= nil then
                return mt.__ipairs(obj)
            elseif mt.__pairs ~= nil then
                return mt.__pairs(obj)
            end
        end
        if #obj > 0 then
            -- array
            return ipairs(obj)
        else
            -- hash
            return map_gen, obj, nil
        end
    elseif (type(obj) == "function") then
        return obj, param, state
    elseif (type(obj) == "string") then
        if #obj == 0 then
            return nil_gen, nil, nil
        end
        return string_gen, obj, 0
    end
    error(string.format('object %s of type "%s" is not iterable',
          obj, type(obj)))
end

local function zip_gen_r(param, state, state_new, ...)
    if #state_new == #param / 2 then
        return state_new, ...
    end

    local i = #state_new + 1
    local gen_x, param_x = param[2 * i - 1], param[2 * i]
    local state_x, r = gen_x(param_x, state[i])
    if state_x == nil then
        return nil
    end
    table.insert(state_new, state_x)
    return zip_gen_r(param, state, state_new, r, ...)
end

local zip_gen = function(param, state)
    return zip_gen_r(param, state, {})
end

-- A special hack for mix to skip last two state, if a wrapped iterator
-- has been passed.
local numargs = function(...)
    local n = select('#', ...)
    if n >= 3 then
        -- Fix last argument.
        local it = select(n - 2, ...)
        if type(it) == 'table' and getmetatable(it) == iterator_mt and
           it.param == select(n - 1, ...) and it.state == select(n, ...) then
            return n - 2
        end
    end

    return n
end

local nil_gen = function(_param, _state)
    return nil
end

-- mix({
--    r,
--    w,
--    cas
-- })
local function mix(...)
    local n = numargs(...)
    if n == 0 then
        return wrap(nil_gen, nil, nil)
    end
    local param = { [2 * n] = 0 }
    local state = { [n] = 0 }

    local i, gen_x, param_x, state_x
    for i=1,n,1 do
        local it = select(n - i + 1, ...)
        gen_x, param_x, state_x = rawiter(it)
        param[2 * i - 1] = gen_x
        param[2 * i] = param_x
        state[i] = state_x
    end

    return wrap(zip_gen, param, state)
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
