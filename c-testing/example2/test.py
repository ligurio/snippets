import unittest
import cffi
import importlib

def load(filename):
    source = open(filename + '.c').read()
    includes = open(filename + '.h').read()
    
    ffibuilder = cffi.FFI()
    ffibuilder.cdef(includes)
    ffibuilder.set_source(filename + '_', source)
    ffibuilder.compile()
    
    module = importlib.import_module(filename + '_')
    return module.lib

class SumTest(unittest.TestCase):
    def setUp(self):
        self.module = load('sum')
        
    def test_zero(self):
        self.assertEqual(self.module.sum(0), 0)

    def test_one(self):
        self.assertEqual(self.module.sum(1), 1)

    def test_multiple(self):
        self.assertEqual(self.module.sum(2), 2)
        self.assertEqual(self.module.sum(4), 2 + 4)

SumTest
