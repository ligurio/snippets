from hypothesis import given
from hypothesis.strategies import text
from lark import Lark
import hypothesis.extra.lark
import unittest
import argparse

class TestEncoding(unittest.TestCase):
        @given(text())
        def test_decode_inverts_encode(self, s):
                print(s)
                m = hypothesis.extra.lark.from_lark("robotstxt.lark", start='hello_world')

if __name__ == '__main__':

    #parser = lark.Lark(GRAMMAR)
    #tree = parser.parse("(5 * (3 << x)) + y - 1")

    parser = argparse.ArgumentParser(description='Generate grammar samples.')
    parser.add_argument('--grammar', dest='grammar',
                        help='file with grammar syntax')
    parser.add_argument('--start', dest='start',
                        help='start terminal')
    args = parser.parse_args()
    print(args.grammar)
    #print(args.accumulate(args.integers))

    unittest.main()
