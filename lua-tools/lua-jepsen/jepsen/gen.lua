-- Module implements a number of generators useful generating operations.
--
-- See also:
--   - https://luafun.github.io/
--   - http://lua-users.org/wiki/IteratorsTutorial
--   - http://jepsen-io.github.io/jepsen/jepsen.generator.html
--
--  fun.rands(0, 3):map(function(x)
--                          return (x == 0 and r()) or
--                                 (x == 1 and w()) or
--                                 (x == 2 and cas())
--                      end):take(n)

local fun = require('fun')
local checks = require('checks')
local math = require('math')

local methods = fun

local iterator_mt = {
    __call = function(self, param, state)
        return self.gen(param, state)
    end;
    __tostring = function(self)
        return '<generator>'
    end;
    __index = methods;
}

local wrap = function(gen, param, state)
    return setmetatable({
        gen = gen,
        param = param,
        state = state
    }, iterator_mt), param, state
end

-- A special hack for zip/chain to skip last two state, if a wrapped iterator
-- has been passed.
local numargs = function(...)
    local n = select('#', ...)
    if n >= 3 then
        -- Fix last argument
        local it = select(n - 2, ...)
        if type(it) == 'table' and getmetatable(it) == iterator_mt and
           it.param == select(n - 1, ...) and it.state == select(n, ...) then
            return n - 2
        end
    end
    return n
end

local mix_gen_r1
local mix_gen_r2 = function(param, state, state_x, ...)
    if state_x == nil then
        local i = state[1]
        i = i + 1
        if param[3 * i - 1] == nil then
            return nil
        end
        local state_x = param[3 * i]
        return mix_gen_r1(param, {i, state_x})
    end
    return {state[1], state_x}, ...
end

mix_gen_r1 = function(param, state)
    local i, state_x = state[1], state[2]
    --local n = 3
    --local i = math.random(1, n)
    local gen_x, param_x = param[3 * i - 2], param[3 * i - 1]

    return mix_gen_r2(param, state, gen_x(param_x, state[2]))
end

-- mix(iter1, iter2, iter3, ...)
local function mix(...)
    local n = numargs(...)
    if n == 0 then
        return wrap(nil_gen, nil, nil)
    end

    -- FIXME
    -- math.randomseed(os.time())

    local param = { [3 * n] = 0 }
    local i, gen_x, param_x, state_x
    for i=1, n, 1 do
        local elem = select(i, ...)
        gen_x, param_x, state_x = fun.iter(elem)
        param[3 * i - 2] = gen_x
        param[3 * i - 1] = param_x
        param[3 * i] = state_x
    end

    return wrap(mix_gen_r1, param, {1, param[3]})
end
methods.mix = mix

local function stagger()
end

return {
    mix = mix,
    stagger = stagger,
}
