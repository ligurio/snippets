--local checks = require("checks")
local checks = require("post_checks")

local function __FILE__() return debug.getinfo(3, 'S').source end
local function __LINE__() return debug.getinfo(3, 'l').currentline end
local function __FUNC__() return debug.getinfo(3, 'n').name or '' end

-- https://www.lua.org/pil/23.1.html

local function trace_l(event, line)
    local s = debug.getinfo(2).short_src
    print(s .. ":" .. line)
end

local function trace(event)
    local s = debug.getinfo(2).short_src
    require("log").info(debug.getinfo(2))
    for i, arg in ipairs{'number', 'number', 'string'} do
        --[[
        local name, val = debug.getlocal(2, i)
        local success = check_many(name, arg, val)
        if not success then
            local fname = debug.getinfo(2, 'n').name
            local fmt = "bad argument #%d to '%s' (%s expected, got %s)"
            local msg = string.format(fmt, i, fname or "?", arg, type(val))
            error(msg, 3)
        end
        ]]
        local name, val = debug.getlocal(2, i)
        local fname = debug.getinfo(2, 'n').name
        print(fname)
        print("name and val", name, val)
        print("i and arg", i, arg)
    end
end

local types

debug.sethook(trace, "r")

local function A(num1, num2, str1)
    --checks('number', 'number', 'string')
    if num1 == 55 then
        return 9, 8
    end
    return 1, 2, "ret-xxx"
end

print(A(56, 66, "FFF"))
--A("x", nil, 3)
