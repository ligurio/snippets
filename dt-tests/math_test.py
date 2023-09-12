#!/usr/bin/python3

# Python datetime library, https://docs.python.org/3/library/datetime.html
# dateutils, https://github.com/hroptatyr/dateutils
# pdd, https://github.com/jarun/pdd
# yest, https://sourceforge.net/projects/yest/
# dateexpr, http://www.eskimo.com/~scs/src/#dateexpr
# allanfalloon's dateutils, https://github.com/alanfalloon/dateutils

"""
import datetime

today = datetime.date.today()
print 'Today    :', today

one_day = datetime.timedelta(days=1)
print 'One day  :', one_day

yesterday = today - one_day
print 'Yesterday:', yesterday

tomorrow = today + one_day
print 'Tomorrow :', tomorrow

print 'tomorrow - yesterday:', tomorrow - yesterday
print 'yesterday - tomorrow:', yesterday - tomorrow

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
