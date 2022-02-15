# pip install --user luaparser

from luaparser import ast
from luaparser import astnodes
from luaparser.astnodes import *
from argparse import ArgumentParser

import difflib
import sys

def generate_str_diff(str1, str2, filename):
    """Return a unified diff of two strings."""

    lines1 = str1.splitlines()
    lines2 = str2.splitlines()
    return difflib.unified_diff(lines1, lines2,
                                filename, filename,
                                "(original)", "(updated)",
                                n=3,
                                lineterm="\n")

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

mutated_src = ast.to_lua_source(tree)
print("Updated source code:", mutated_src)
print("Unified diff")
udiff = generate_str_diff(src, mutated_src, args.filename)
# sys.stdout.writelines(udiff)
print(''.join(udiff))
