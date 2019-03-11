#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hypothesis import given
from hypothesis.strategies import text
from lark import Lark
import hypothesis.extra.lark
import argparse

@given(text())
def generate_tests(self, grammar, start):
    print(self, grammar, start)
    m = hypothesis.extra.lark.from_lark(grammar, start=start)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Generate grammar samples.')
    parser.add_argument('--grammar', dest='grammar',
                        help='file with grammar syntax')
    parser.add_argument('--start', dest='start',
                        help='start terminal')
    args = parser.parse_args()
    print(args.grammar, args.start)
    generate_tests(args.grammar, args.start)
