#!/usr/bin/python3

import atheris
import signal
from datetime import datetime as dt
import sys

atheris.instrument_all()

def signal_handler(sig, frame):
    sys.exit(0)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    str_date = fdp.ConsumeString(10)
    str_format = fdp.ConsumeString(10)
    try:
        dt.strptime(str_date, str_format)
    except ValueError:
        return -1


signal.signal(signal.SIGINT, signal_handler)
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
