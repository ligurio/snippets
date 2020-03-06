import unittest
import pycparser
import cffi
import importlib

class FunctionList(pycparser.c_ast.NodeVisitor):
    def __init__(self, source):
        self.funcs = set()
        self.visit(pycparser.CParser().parse(source))
        
    def visit_FuncDef(self, node):
        self.funcs.add(node.decl.name)

def load(filename):
    name = filename + '_' + uuid.uuid4().hex

    source = open(filename + '.c').read()
    # preprocess all header files for CFFI
    includes = preprocess(''.join(re.findall('\s*#include\s+.*', source)))

    # prefix external functions with extern "Python+C"
    local_functions = FunctionList(preprocess(source)).funcs
    includes = convert_function_declarations(includes, local_functions)

    ffibuilder = cffi.FFI()
    ffibuilder.cdef(includes)
    ffibuilder.set_source(name, source)
    ffibuilder.compile()

    module = importlib.import_module(name)
    # return both the library object and the ffi object
    return module.lib, module.ffi

class CFFIGenerator(pycparser.c_generator.CGenerator):
    def __init__(self, blacklist):
        super().__init__()
        self.blacklist = blacklist
        
    def visit_Decl(self, n, *args, **kwargs):
        result = super().visit_Decl(n, *args, **kwargs)
        if isinstance(n.type, pycparser.c_ast.FuncDecl):
            if n.name not in self.blacklist:
                return 'extern "Python+C" ' + result
        return result

def convert_function_declarations(source, blacklist):
    return CFFIGenerator(blacklist).visit(pycparser.CParser().parse(source))

class GPIOTest(unittest.TestCase):
    def setUp(self):
        self.module, self.ffi = load('gpio')
        
    def test_read_gpio0(self):
        @self.ffi.def_extern()
        def read_gpio0():
            return 42
        self.assertEqual(self.module.read_gpio(0), 42)
        
    def test_read_gpio1(self):
        read_gpio1 = unittest.mock.MagicMock(return_value=21)
        self.ffi.def_extern('read_gpio1')(read_gpio1)
        self.assertEqual(self.module.read_gpio(1), 21)
        read_gpio1.assert_called_once_with()
        
GPIOTest
