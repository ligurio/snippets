--[[
Lua parsers

- Lua https://github.com/lunarmodules/luacheck/blob/master/src/luacheck/parser.lua
- Lua https://github.com/lunarmodules/luacheck/blob/master/src/luacheck/lexer.lua
- Lua https://github.com/andremm/lua-parser (lpeglabel)
- Lua https://github.com/fab13n/metalua-parser (lpeglabel)
- Lua https://github.com/thenumbernine/lua-parser
- Python https://github.com/SirAnthony/slpp
- Python https://github.com/boolangery/py-lua-parser
- C tree-sitter https://github.com/Azganoth/tree-sitter-lua

References:

- Fuzzili https://saelo.github.io/papers/thesis.pdf
- Fuzzili https://github.com/googleprojectzero/fuzzilli/blob/main/Sources/Fuzzilli/Mutators/OperationMutator.swift
- MongoDB https://engineering.mongodb.com/post/mongodbs-javascript-fuzzer-creating-chaos
- MongoDB https://engineering.mongodb.com/post/mongodbs-javascript-fuzzer-harnessing-havoc
- JS https://github.com/MashaSamoylova/DFuzzer

https://www.lua.org/wshop18/Ierusalimschy.pdf
http://www.lua.org/manual/5.2/manual.html#2.5
LuaJIT bugs https://github.com/tarantool/tarantool/wiki/Vanilla-LuaJIT-sync-status

https://code.google.com/archive/p/lua-checker/

LuaFish
  - https://github.com/davidm/lua-fish
  - http://lua-users.org/wiki/LuaFish

MetaLua
  - https://github.com/fab13n/metalua
  - http://lua-users.org/wiki/DetectingUndefinedVariables
]]

--[[
Mutations:

- превратить выражение в функцию: "expr" -> "function() return expr end"
- превратить выражение в loadstring: "expr" -> loadstring("return expr")
- gc: collectgarbage("collect"), https://www.lua.org/wshop18/Ierusalimschy.pdf
- "expr" -> "expr + random() - random()"
	inf (1/0)
	nan (0/0)
	math.huge and -math.huge, http://www.lua.org/manual/5.1/manual.html#pdf-math.huge
	big = 1e309
	small = -1e309
- добавить двойное отрицание: "expr" -> "not not expr"
- "expr" -> "if (true) then expr else expr"
- "expr" -> "if (generated_boolean_expr) then expr else generated_expr"
- "expr" -> "generated_boolean_expr < 0 and false or true"
- заменить что-то на генератор luafun
- https://github.com/ItsLastDay/KotlinFuzzer/blob/master/fuzzer/src/main/kotlin/ru/au/kotlinfuzzer/mutation/mutation.kt
- X -> regex (string.match(X, X))
- (!) expr -> "function() ok, ... = pcall(expr) return ... end"
- обратные операции, типа string -> buffer.decode(buffer.encode(string))
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

os.exit(0)
