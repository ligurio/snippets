"""
Lua parsers

- Lua https://github.com/lunarmodules/luacheck/blob/master/src/luacheck/parser.lua
- Lua https://github.com/lunarmodules/luacheck/blob/master/src/luacheck/lexer.lua
- Lua https://github.com/andremm/lua-parser
- Python https://github.com/SirAnthony/slpp
- Python https://github.com/boolangery/py-lua-parser
- C tree-sitter https://github.com/Azganoth/tree-sitter-lua

References:

- Fuzzili https://saelo.github.io/papers/thesis.pdf
- Fuzzili https://github.com/googleprojectzero/fuzzilli/blob/main/Sources/Fuzzilli/Mutators/OperationMutator.swift
- MongoDB https://engineering.mongodb.com/post/mongodbs-javascript-fuzzer-creating-chaos
- MongoDB https://engineering.mongodb.com/post/mongodbs-javascript-fuzzer-harnessing-havoc

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

"""
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

"""

# pip install luaparser

from luaparser import ast
from luaparser import astnodes
from luaparser.astnodes import *
from argparse import ArgumentParser

import difflib
import sys

def generate_str_diff(str1, str2):
    """Return a unified diff of two strings."""

    lines1 = str1.splitlines()
    lines2 = str2.splitlines()
    return difflib.unified_diff(lines1, lines2, 'str1', 'str2',
                                "(original)", "(updated)",
                                lineterm="")

parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="File with Lua source code", metavar="FILE")
parser.add_argument("-q", "--quiet",
                    action="store_false", dest="verbose", default=True,
                    help="Don't print status messages to stdout")

args = parser.parse_args()

if not args.filename:
    print("No file is specified.")
    sys.exit(1)

src = ""
with open(args.filename) as f:
    src = f.read()

print(src)

class Mutation(ast.ASTVisitor):
    def visit_Number(self, node):
        node.n = "string.match('{}', '{}')".format(node.n, node.n)

    def visit_Name(self, node):
        node = "string.match('{}', '{}')".format(node.n, node.n)

    def visit_Name(self, node):
        pass

tree = ast.parse(src)
Mutation().visit(tree)

for node in ast.walk(tree):
    if isinstance(node, Chunk):
        print("Chunk")
        pass
    if isinstance(node, Block):
        print("Block")
        pass
    if isinstance(node, LocalAssign):
        print("LocalAssign")
        pass
    if isinstance(node, Name):
        new_value = "string.match('{}', '{}')".format(node, node)
        old_value = node
        # print("{} --> {}".format(old_value, new_value))
        node = new_value
    if isinstance(node, Number):
        old_value = node.n
        new_value = "string.match('{}', '{}')".format(node.n, node.n)
        # print("{} --> {}".format(old_value, new_value))
        node.n = new_value

print("Updated source code:", ast.to_lua_source(tree))
