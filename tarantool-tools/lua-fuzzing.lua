--[[
How to run:

$ luarocks --local install lua-parser
$ eval `luarocks path`
$ tarantool lua-fuzzing.lua "for i=1,10 do print(i) end"
]]

local parser = require("lua-parser.parser")
local pp = require("lua-parser.pp")

if #arg ~= 1 then
    print("Usage: lua-fuzzing.lua <string>")
    os.exit(1)
end

local ast, error_msg = parser.parse(arg[1], "example.lua")
if not ast then
    print(error_msg)
    os.exit(1)
end

pp.print(ast)
print(pp.tostring(ast))
print(pp.dump(ast))

os.exit(0)
