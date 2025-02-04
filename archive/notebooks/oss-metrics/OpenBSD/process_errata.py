#!/usr/local/bin/python

import csv
import re
import requests

def touched_files(patch):

    for line in patch.split("\n"):
        match = re.match('^Index: (.*)', line)
        if match:
            print match.group(1)

with open('errata.csv', 'rb') as errata_file:
    errata = csv.reader(errata_file, delimiter=',', quotechar='"')
    for idx, row in enumerate(errata):
        if idx == 0 or idx == 8 or idx == 96:
            continue
        print ', '.join(row)
        patch_url = row[2]
        if patch_url and patch_url is not "-":
            r = requests.get(patch_url)
            r.raise_for_status()
            touched_files(r.text)
