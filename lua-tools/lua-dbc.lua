-- local inspect = require('inspect')

if type(jit) ~= 'table' then
   print('PUC Rio Lua is unsupported')
   os.exit()
end

local function __FILE__() return debug.getinfo(3, 'S').source end
local function __LINE__() return debug.getinfo(3, 'l').currentline end
local function __FUNC__() return debug.getinfo(3, 'n').name or '' end

-- "require no more, promise no less"
-- It is a PoC of Design by Contract for Lua using native debug module.
-- Unfortunately it doesn't work as expected for two reasons:
-- 1. it is not possible to obtain return values in function in runtime
-- 2. it is not possible to set more than one hook to trace call and
--    exit in function
-- How to run: tarantool dbc.lua
-- See also support DbC in Go https://github.com/ligurio/go-contracts

-- uncomment to trigger assert
-- local promise = 'p1 < p2'
local promise = 'p1 > p2'

function check_promise(condition, params)
    print('promise: ' .. condition)
    for k, v in pairs(params) do
        condition = condition:gsub(k, v)
    end
    condition = 'return ' .. condition
    print('updated promise: ' .. condition)
    local c = loadstring(condition)

    return c()
end

function precondition_hook(event)
    local name = debug.getinfo(2).name or ''
    local fn_name = __FUNC__()
    local argc = debug.getinfo(2).nparams
    local argv = {}
    if fn_name == 'hello' then
        print('precondition_hook triggered ' .. fn_name)
        for i = 1, argc do
            arg, value = debug.getlocal(2, i)
            argv[arg] = value
        end
        local res = check_promise(promise, argv)
        print('passed? ' .. tostring(res))
        if not res then
            print('===============================================================')
            print('Broken contract, line: ' .. debug.getinfo(2).currentline)
            print('Broken condition: ' .. promise .. ' in a function ' .. fn_name)
            print('Traceback: ' .. debug.traceback(1, 2))
        end
    end
end

function postcondition_hook(event)
    --local info = debug.getinfo(2)
    --print(inspect.inspect(info))
end

function dbc_enable()
    print('contracts are enabled')
    -- note: sethook() overrides previous hook
    debug.sethook(precondition_hook, 'l')
    --debug.sethook(postcondition_hook, 'r')
end

local function pre(condition)
    --print('require: ' .. condition)
    -- make sure params are occured in condition
    -- string.gmatch("Hello Lua user", "%a+")
end

local function post(condition)
    --print('ensure: ' .. condition)
    -- make sure params are occured in condition
    -- string.gmatch("Hello Lua user", "%a+")
end

------------------------------------------

local function hello(p1, p2)
    pre('p1 > p2')
    post('p1 > p2')
    return nil
end

-- using DbC has performance impact
dbc_enable()
-- execute function with certain parameters
hello(2, 1)
