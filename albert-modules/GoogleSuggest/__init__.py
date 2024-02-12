"""GoogleSuggest - Autocomplete Google searches."""

import os
import subprocess
from collections import namedtuple
import requests
from pathlib import Path

try:
    import albert as v0
except:
    pass

__iid__ = "PythonInterface/v0.2"
__title__ = "Google autocomplete search"
__prettyname__ = "Google Suggest"
__version__ = "0.0.1"
__authors__ = "Jairo 'jairovsky'"
__triggers__ = "g "
__homepage__ = (
        "https://github.com/jairovsky/albert-extensions/"
)
__exec_deps__ = []
__py_deps__ = []

icon_path = str(Path(__file__).parent / "/google.png")

def handleQuery(query):
    if not query.isTriggered:
        return
    stripped = query.string.strip().lower()
    if stripped:
        results = []
        results.append(
            v0.Item(
                id=__title__,
                icon=icon_path,
                text="Give me color name, rgb triad or hex value",
                subtext="Supports fuzzy-search...",
            )
        )
        for line in qGoogle(stripped):
            results.append(v0.Item(id="%s%s" % (__prettyname__, line),
                                   icon=icon_path,
                                   text="%s" % (line),
                                   subtext="Open suggestion",
                                   actions=[ v0.ProcAction("Open suggestion",
                                           ["xdg-open", "https://google.com/search?q=%s" % line])]))
        return results

def qGoogle(q):
    gquery = 'https://www.google.com/complete/search?q=%s&client=firefox' % q
    suggs = requests.get(url = gquery).json()[1]
    return suggs

# For testing.
try:
    from sys import argv
    if __name__ == '__main__':
        print(qGoogle(argv[1]))
except:
    pass
