--[[
-- Jepsen generators http://jepsen-io.github.io/jepsen/jepsen.generator.html
-- Lua stateless iterators https://www.lua.org/pil/7.3.html
--]]

local fun = require('fun')
local checks = require('checks')
local inspect = require('inspect')
local errors = require('errors')

local BuildGeneratorError = errors.new_class('BuildGeneratorError', {capture_stack = false})

-- Takes an operation and fills in missing fields for :type, :process, and
-- :time using context.
-- Returns :pending if no process is free.
--local function fill_in_op()
--end

local function stagger()
    -- add delay to start time
end

-- TODO
local function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

-- mix({
--    r(),
--    w(),
--    cas()
-- })
--
-- mix({
--    {'w'},
--    {'r'},
-- })
local function mix(ops)
    checks('table')

    local fn_body = 'return '
    for i, op in ipairs(ops) do
        if fn_body ~= 'return ' then
            fn_body = fn_body .. ' or '
        end
        if type(op) == 'function' then
            local err
            op, err = pcall(op)
            if err ~= nil then
                return nil, BuildGeneratorError:new('Client has a wrong interface')
            end
        end
        fn_body = fn_body .. string.format('(x == %d and "%s")',
						i,
                                                inspect.inspect(op, {newline = ' ', indent = ''}))
    end
    print('XXXXXXXXXXXXXXXXXXXX', fn_body, 'XXXXXXXXXXXXXXXXXXXX')
    local fn = loadstring(fn_body)

    return fun.rands(0, #ops):map(fn)
end

local function cycle(table)
    checks('table', 'number|nil')
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
    cycle = cycle,
    mix = mix,
    filter = filter,
    map = map,
    take = take,
    take_while = take_while,
    stagger = stagger,
    chain = chain,
    dump = dump,
}
