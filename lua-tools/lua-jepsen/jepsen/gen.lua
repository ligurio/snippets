-- Module implements a number of generators useful for generating operations.
--
-- References:
--   - https://luafun.github.io/
--   - http://lua-users.org/wiki/IteratorsTutorial
--   - http://jepsen-io.github.io/jepsen/jepsen.generator.html
--
-- local w = function() return { f = 'w', v = math.random(1, 10) } end
-- local r = function() return { f = 'r', v = nil } end
-- gen.rands(0, 2):map(function(x)
--                         return (x == 0 and r()) or
--                                (x == 1 and w()))
--                     end):take(100)
--
-- local w = function(x) return { f = 'w', v = x } end
-- gen.map(w, gen.rands(1, 10):take(50))

local clock = require('clock')
local fun = require('fun')
--local checks = require('checks')
--local math = require('math')

local methods = {}
local exports = {}

local iterator_mt = {
    __call = function(self, param, state)
        return self.gen(param, state)
    end,
    __tostring = function(self)
        return '<generator>'
    end,
    __index = methods,
}

local wrap = function(gen, param, state)
    return setmetatable({
        gen = gen,
        param = param,
        state = state
    }, iterator_mt), param, state
end
methods.wrap = wrap

local unwrap = function(self)
    return self.gen, self.param, self.state
end
methods.unwrap = unwrap

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

local method0 = function(fun)
    return function(self)
        return fun(self.gen, self.param, self.state)
    end
end

local export0 = function(fun)
    return function(gen, param, state)
        return fun(rawiter(gen, param, state))
    end
end

-- Tools.

local call_if_not_empty = function(state_x, ...)
    if state_x == nil then
        return nil
    end
    return state_x
end

local return_if_not_empty = function(state_x, ...)
    if state_x == nil then
        return nil
    end
    return ...
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

-- Basic Functions.
local iter = function(...) return wrap(fun.iter(...):unwrap()) end
methods.iter = iter
exports.iter = iter

local each = function(...) return wrap(fun.each(...):unwrap()) end
--methods.each = each
--exports.each = each
--methods.for_each = each
--exports.for_each = each
--methods.foreach = each
--exports.foreach = each

-- Generators: Finite Generators.
local range = function(...) return wrap(fun.range(...):unwrap()) end
methods.range = range
exports.range = range

-- Generators: Infinity Generators.
local duplicate = function(...) return wrap(unwrap(fun.duplicate(...))) end
--methods.duplicate = duplicate
--exports.duplicate = duplicate
--methods.xrepeat = duplicate
--exports.xrepeat = duplicate
--methods.replicate = duplicate
--exports.replicate = duplicate

local tabulate = function(...) return wrap(fun.tabulate(...)) end
--methods.tabulate = tabulate
--exports.tabulate = tabulate

local zeros = function(...) return wrap(fun.zeros(...)) end
--methods.zeros = zeros
--exports.zeros = zeros

local ones = function(...) return wrap(fun.ones(...)) end
--methods.ones = ones
--exports.ones = ones

-- Generators: Random sampling.
local rands = function(...) return wrap(fun.rands(...):unwrap()) end
methods.rands = rands
exports.rands = rands

-- Slicing: Basic.
local nth = function(...) return wrap(fun.nth(...)) end
--methods.nth = nth
--exports.nth = nth

local head = function(...) return wrap(fun.head(...)) end
--methods.head = head
--exports.head = head
--methods.car = head
--exports.car = head

local tail = function(...) return wrap(fun.tail(...)) end
--methods.tail = tail
--exports.tail = tail
--exports.cdr = tail

-- Slicing: Subsequences.
local take_n = function(...) return wrap(fun.take_n(...):unwrap()) end
methods.take_n = take_n
exports.take_n = take_n

local take_while = function(...) return wrap(unwrap(fun.take_while(...))) end
methods.take_while = take_while
exports.take_while = take_while

local take = function(n_or_fun, ...)
    if type(n_or_fun) == 'number' then
        return take_n(n_or_fun, ...)
    else
        return take_while(n_or_fun, ...)
    end
end
methods.take = take
exports.take = take

local drop_n = function(...) return wrap(fun.drop_n(...)) end
--methods.drop_n = drop_n
--exports.drop_n = drop_n

local drop_while = function(...) return wrap(fun.drop_while(...)) end
--methods.drop_while = drop_while
--exports.drop_while = drop_while

local drop = function(...) return wrap(fun.drop(...)) end
--methods.drop = drop
--exports.drop = drop

local span = function(...) return wrap(fun.span(...)) end
--methods.span = span
--exports.span = span
--methods.split = span
--exports.split = span
--methods.split_at = span
--exports.split_at = span

-- Indexing.
local index = function(...) return wrap(fun.index(...)) end
--methods.index = index
--exports.index = index
--methods.index_of = index
--exports.index_of = index
--methods.elem_index = index
--exports.elem_index = index

local indexes = function(...) return wrap(fun.indexes(...)) end
--methods.indexes = indexes
--exports.indexes = indexes
--methods.indices = indexes
--exports.indices = indexes
--methods.elem_indexes = indexes
--exports.elem_indexes = indexes
--methods.elem_indices = indexes
--exports.elem_indices = indexes

-- Filtering.
local filter = function(...) return wrap(fun.filter(...)) end
--methods.filter = filter
--exports.filter = filter
--methods.remove_if = remove_if
--exports.remove_if = remove_if

local grep = function(...) return wrap(fun.grep(...)) end
--methods.grep = grep
--exports.grep = grep

local partition = function(...) return wrap(fun.partition(...)) end
--methods.partition = partition
--exports.partition = partition

-- Reducing: Folds.
--methods.foldl = fun.foldl
--exports.foldl = fun.foldl
--methods.reduce = foldl
--exports.reduce = foldl

local length = fun.length
methods.length = length
exports.length = length

local totable = function(gen_x, param_x, state_x)
    local tab, key, val = {}
    while true do
        state_x, val = gen_x(param_x, state_x)
        if state_x == nil then
            break
        end
        table.insert(tab, val)
    end
    return tab
end
methods.totable = method0(totable)
exports.totable = export0(totable)

local tomap = function()
end
--methods.tomap = method0(tomap)
--exports.tomap = export0(tomap)

-- Reducing: Predicates.
local is_prefix_of = function(...) return wrap(fun.is_prefix_of(...)) end
--methods.is_prefix_of = is_prefix_of
--exports.is_prefix_of = is_prefix_of

local is_null = function(...) return wrap(fun.is_null(...)) end
--methods.is_null = is_null
--exports.is_null = is_null

local all = function(...) return wrap(fun.all(...)) end
--methods.all = all
--exports.all = all
--methods.every = all
--exports.every = all

local any = function(...) return wrap(fun.any(...)) end
--methods.any = any
--exports.any = any
--methods.some = any
--exports.some = any

-- Reducing: Special folds.
local sum = function(...) return wrap(fun.sum(...)) end
--methods.sum = sum
--exports.sum = sum

local product = function(...) return wrap(fun.product(...)) end
--methods.product = product
--exports.product = product

local min = function(...) return wrap(fun.min(...)) end
--methods.min = min
--exports.min = min
--methods.minimum = min
--exports.minimum = min

local min_by = function(...) return wrap(fun.min_by(...)) end
--methods.min_by = min_by
--exports.min_by = min_by
--methods.minimum_by = min_by
--exports.minimum_by = min_by

local max = function(...) return wrap(fun.max(...)) end
--methods.max = max
--exports.max = max
--methods.maximum = max
--exports.maximum = max

local max_by = function(...) return wrap(fun.max_by(...)) end
--methods.max_by = max_by
--exports.max_by = max_by
--methods.maximum_by = max_by
--exports.maximum_by = max_by

-- Transformations.
local map = function(...) return wrap(fun.map(...):unwrap()) end
local map = function(...)
    local function x(obj, ...)
        if type(obj) == 'table' then
            local mt = getmetatable(obj);
            if mt ~= nil then
                if mt == iterator_mt then
                    assert(nil)
                    return wrap(obj.gen, obj.param, obj.state)
                end
            end
        end
        return ...
    end

    return x(fun.map(...))
end
--methods.map = map
--exports.map = map

local enumerate = function(...) return wrap(fun.enumerate(...)) end
--methods.enumerate = enumerate
--exports.enumerate = enumerate

local intersperse = function(...) return wrap(fun.intersperse(...)) end
--methods.intersperse = intersperse
--exports.intersperse = intersperse

-- Compositions.
local zip = function(...) return wrap(fun.zip(...)) end
--methods.zip = zip
--exports.zip = zip

local cycle = function(...) return wrap(fun.cycle(...)) end
--methods.cycle = cycle
--exports.cycle = cycle

local chain = function(...) return wrap(fun.chain(...)) end
--methods.chain = chain
--exports.chain = chain

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

local function mix(...)
    local n = numargs(...)
    if n == 0 then
        return wrap(nil_gen, nil, nil)
    end

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
--methods.mix = mix
--exports.mix = mix

local function stagger()
    -- TODO
end
--methods.stagger = stagger
--exports.stagger = stagger

local function time_limit(timeout, gen, param, state)
    -- TODO
end
--methods.time_limit = time_limit
--exports.time_limit = time_limit

return exports
