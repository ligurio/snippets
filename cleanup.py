# https://stackoverflow.com/questions/982682/mark-data-as-sensitive-in-python/983525#983525
# https://www.sjoerdlangkemper.nl/2016/06/09/clearing-memory-in-python/

# Secure cleanup strings in Python.
# How-to: Run with uncommented os.abort() and then make sure that string content is
# absent in core file.

from ctypes import memset
import sys
import os
import gc

def erase(var_to_erase):
    strlen = len(var_to_erase)
    offset = sys.getsizeof(var_to_erase) - strlen - 1
    memset(id(var_to_erase) + offset, 0, strlen)
    print("Clearing 0x%08x, size %i bytes" % (offset, strlen))

class TweedleDee(object):
    def __init__(self):
        self.value = 'XXXXXXXXXXXXX'

    # https://docs.python.org/3/reference/datamodel.html#object.__delete__
    def __delete__(self, instance):
        print("Calling __delete__")
        erase(self.value)
        del self.value

    # https://docs.python.org/3/reference/datamodel.html#object.__del__
    def __del__(self):
        print("Calling __del__")


class TweedleDoom(object):
    exp = TweedleDee()


f = TweedleDoom()
del f.exp
gc.collect()

os.abort()
