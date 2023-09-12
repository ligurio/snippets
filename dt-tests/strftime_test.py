#!/usr/bin/python3

# TODO: https://pandas.pydata.org/docs/reference/api/pandas.Timestamp.strftime.html

import atheris
import signal
from datetime import datetime as dt
import sys

def signal_handler(sig, frame):
    print("Hello!")
    sys.exit(0)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        date = dt.fromtimestamp(fdp.ConsumeInt(5))
    except ValueError:
        return
    dt_str = date.strftime('%a %m %y')


signal.signal(signal.SIGINT, signal_handler)
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
