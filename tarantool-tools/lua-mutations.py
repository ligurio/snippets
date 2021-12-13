"""
https://github.com/lunarmodules/luacheck/blob/master/src/luacheck/parser.lua
https://github.com/lunarmodules/luacheck/blob/master/src/luacheck/lexer.lua

https://github.com/andremm/lua-parser
https://github.com/boolangery/py-lua-parser
garbage collector
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
"""

from luaparser import ast
from luaparser import astnodes
from luaparser.astnodes import *

src = "local a = 42"
src = """
buffer = require 'buffer'
msgpack = require 'msgpack'
ffi = require 'ffi'

buf = buffer.ibuf()

msgpack.encode('test', buf)
collectgarbage()       -- forces a garbage collection cycle

local a = 45
local b = 'aabbcc'

decimal = require('decimal')
collectgarbage()       -- forces a garbage collection cycle
a = decimal.new('1e37')
b = decimal.new('1e-38')
c = decimal.new('1')
d = decimal.new('0.1234567')
e = decimal.new('123.4567')
"""

class Mutation(ast.ASTVisitor):
    def visit_Number(self, node):
        node.n = "string.match('{}', '{}')".format(node.n, node.n)

    def visit_Name(self, node):
        print("dddd")
        node = "string.match('{}', '{}')".format(node.n, node.n)

    def visit_Name(self, node):
        print("dddd")

tree = ast.parse(src)
# Mutation().visit(tree)

for node in ast.walk(tree):
    if isinstance(node, Chunk):
        pass
    if isinstance(node, Block):
        pass
    if isinstance(node, LocalAssign):
        pass
    if isinstance(node, Name):
        new_value = "string.match('{}', '{}')".format(node, node)
        old_value = node
        print("{} --> {}".format(old_value, new_value))
        node = new_value
    if isinstance(node, Number):
        old_value = node.n
        new_value = "string.match('{}', '{}')".format(node.n, node.n)
        print("{} --> {}".format(old_value, new_value))
        node.n = new_value

print(ast.to_lua_source(tree))
