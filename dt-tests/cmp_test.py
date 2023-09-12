#!/usr/bin/python3

"""
import datetime
s = '04/21/2013'
d = datetime.datetime.strptime(s, '%m/%d/%Y') + datetime.timedelta(days=1)
print(d.strftime('%m/%d/%Y'))
04/22/2013

python -c 'import datetime;print(datetime.datetime.now() - datetime.timedelta(days=1,hours=1,minutes=30))'

https://www.tutorialspoint.com/How-to-perform-arithmetic-operations-on-a-date-in-Python
https://pymotw.com/2/datetime/
"""

import atheris

with atheris.instrument_imports():
    import datetime
    import sys


def TestOneInput(data):
    # from datetime import datetime as dt
    # now = dt.now()
    pass


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
