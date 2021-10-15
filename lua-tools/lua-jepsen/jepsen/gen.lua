-- Module implements a number of generators useful for generating operations.
--
-- References:
--   - https://luafun.github.io/
--   - http://lua-users.org/wiki/IteratorsTutorial
--   - http://jepsen-io.github.io/jepsen/jepsen.generator.html
--
-- local w = function() return { f = 'w', v = math.random(1, 10) } end
-- local r = function() return { f = 'r', v = nil } end
-- fun.rands(0, 2):map(function(x)
--                         return (x == 0 and r()) or
--                                (x == 1 and w()))
--                     end):take(100)
--
-- local w = function(x) return { f = 'w', v = x } end
-- fun.map(w, fun.rands(1, 10):take(50))


local clock = require('clock')
local fun = require('fun')
--local checks = require('checks')
--local math = require('math')

local methods = {}

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

--

-- Basic Functions.
local iter = function(...) return wrap(fun.iter(...)) end
methods.iter = iter

local each = function(...) return wrap(fun.each(...)) end
methods.each = each
methods.for_each = each
methods.foreach = each

-- Generators: Finite Generators.
local range = function(...) return wrap(fun.range(...)) end
methods.range = range

-- Generators: Infinity Generators.
local duplicate = function(...) return wrap(fun.duplicate(...)) end
methods.duplicate = duplicate
methods.xrepeat = duplicate
methods.replicate = duplicate

local tabulate = function(...) return wrap(fun.tabulate(...)) end
methods.tabulate = tabulate

local zeros = function(...) return wrap(fun.zeros(...)) end
methods.zeros = zeros

local ones = function(...) return wrap(fun.ones(...)) end
methods.ones = ones

-- Generators: Random sampling.
local rands = function(...) return wrap(fun.rands(...)) end
methods.rands = rands

-- Slicing: Basic.
local nth = function(...) return wrap(fun.nth(...)) end
methods.nth = nth

local head = function(...) return wrap(fun.head(...)) end
methods.head = head
methods.car = head

local tail = function(...) return wrap(fun.tail(...)) end
methods.tail = tail
methods.cdr = tail

-- Slicing: Subsequences.
local take_n = function(...) return wrap(fun.take_n(...)) end
methods.take_n = take_n

local take_while = function(...) return wrap(fun.take_while(...)) end
methods.take_while = take_while

local take = function(...) return wrap(fun.take(...)) end
methods.take = take

local drop_n = function(...) return wrap(fun.drop_n(...)) end
methods.drop_n = drop_n

local drop_while = function(...) return wrap(fun.drop_while(...)) end
methods.drop_while = drop_while

local drop = function(...) return wrap(fun.drop(...)) end
methods.drop = drop

local span = function(...) return wrap(fun.span(...)) end
methods.span = span
methods.split = span
methods.split_at = span

-- Indexing.
local index = function(...) return wrap(fun.index(...)) end
methods.index = index
methods.index_of = index
methods.elem_index = index

local indexes = function(...) return wrap(fun.indexes(...)) end
methods.indexes = indexes
methods.indices = indexes
methods.elem_indexes = indexes
methods.elem_indices = indexes

-- Filtering.
local filter = function(...) return wrap(fun.filter(...)) end
methods.filter = filter

local remove_if = function(...) return wrap(fun.remove_if(...)) end
methods.remove_if = remove_if

local grep = function(...) return wrap(fun.grep(...)) end
methods.grep = grep

local partition = function(...) return wrap(fun.partition(...)) end
methods.partition = partition

-- Reducing: Folds.
local foldl = function(...) return wrap(fun.foldl(...)) end
methods.foldl = foldl
methods.reduce = foldl

local length = function(...) return wrap(fun.length(...)) end
methods.length = length

local totable = function(...) return wrap(fun.totable(...)) end
methods.totable = totable

local tomap = function(...) return wrap(fun.tomap(...)) end
methods.tomap = tomap

-- Reducing: Predicates.
local is_prefix_of = function(...) return wrap(fun.is_prefix_of(...)) end
methods.is_prefix_of = is_prefix_of

local is_null = function(...) return wrap(fun.is_null(...)) end
methods.is_null = is_null

local all = function(...) return wrap(fun.all(...)) end
methods.all = all
methods.every = all

local any = function(...) return wrap(fun.any(...)) end
methods.any = any
methods.some = any

-- Reducing: Special folds.
local sum = function(...) return wrap(fun.sum(...)) end
methods.sum = sum

local product = function(...) return wrap(fun.product(...)) end
methods.product = product

local min = function(...) return wrap(fun.min(...)) end
methods.min = min
methods.minimum = min

local min_by = function(...) return wrap(fun.min_by(...)) end
methods.min_by = min_by
methods.minimum_by = min_by

local max = function(...) return wrap(fun.max(...)) end
methods.max = max
methods.maximum = max

local max_by = function(...) return wrap(fun.max_by(...)) end
methods.max_by = max_by
methods.maximum_by = max_by

-- Transformations.
local map = function(...) return wrap(fun.map(...)) end
methods.map = map

local enumerate = function(...) return wrap(fun.enumerate(...)) end
methods.enumerate = enumerate

local intersperse = function(...) return wrap(fun.intersperse(...)) end
methods.intersperse = intersperse

-- Compositions.
local zip = function(...) return wrap(fun.zip(...)) end
methods.zip = zip

local cycle = function(...) return wrap(fun.cycle(...)) end
methods.cycle = cycle

local chain = function(...) return wrap(fun.chain(...)) end
methods.chain = chain

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
methods.stagger = stagger

local function time_limit(timeout, gen, param, state)
end
methods.time_limit = time_limit

return methods

--[[
return {
    -- Basic Functions
    iter = iter,
    each = each,
    for_each = each,
    foreach = each,
    -- Generators: Finite Generators
    range = range,
    -- Generators: Infinity Generators
    duplicate = duplicate,
    xrepeat = duplicate,
    replicate = duplicate,
    tabulate = tabulate,
    zeros = zeros,
    ones = ones,
    -- Generators: Random sampling
    rands = rands,
    -- Slicing: Basic
    nth = nth,
    head = head,
    car = head,
    tail = tail,
    cdr = tail,
    -- Slicing: Subsequences
    take_n = take_n,
    take_while = take_while,
    take = take,
    drop_n = drop_n,
    drop_while = drop_while,
    drop = drop,
    span = span,
    split = span,
    split_at = span,
    -- Indexing
    index = index,
    index_of = index,
    elem_index = index,
    indexes = indexes,
    indices = indexes,
    elem_indexes = indexes,
    elem_indices = indexes,
    -- Filtering
    filter = filter,
    remove_if = remove_if,
    grep = grep,
    partition = partition,
    -- Reducing: Folds
    foldl = foldl,
    reduce = foldl,
    length = length,
    totable = totable,
    tomap = tomap,
    -- Reducing: Predicates
    is_prefix_of = is_prefix_of,
    is_null = is_null,
    all = all,
    every = all,
    any = any,
    some = any,
    -- Reducing: Special folds
    sum = sum,
    product = product,
    min = min,
    minimum = min,
    min_by = min_by,
    minimum_by = min_by,
    max = max,
    maximum = max,
    max_by = max_by,
    maximum_by = max_by,
    -- Transformations
    map = map,
    enumerate = enumerate,
    intersperse = intersperse,
    -- Compositions
    zip = zip,
    cycle = cycle,
    chain = chain,

    --
    mix = mix,
    stagger = stagger,
    time_limit = time_limit,
}
]]
