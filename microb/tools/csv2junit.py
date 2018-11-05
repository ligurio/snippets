#!/usr/bin/env python
#
# csv2junit.py
#
# name,iterations,real_time,cpu_time,bytes_per_second,items_per_second,label
# "BM_SetInsert/1024/1",65465,17890.7,8407.45,475768,118942,
# "BM_SetInsert/1024/8",116606,18810.1,9766.64,3.27646e+06,819115,
# "BM_SetInsert/1024/10",106365,17238.4,8421.53,4.74973e+06,1.18743e+06,

import sys
import os
import csv

if len(sys.argv) > 1:
    csv_file = open(sys.argv[1])
else:
    csv_file = sys.stdin

csv_reader = csv.DictReader(csv_file)
next(csv_reader, None)       # skip the headers

xml = sys.stdout
xml.write('<?xml version="1.0"?>' + "\n")
xml.write('<testsuites>' + "\n")
xml.write('\t<testsuite>' + "\n")
for row in csv_reader:
    xml.write('\t\t<testcase time=' + row["real_time"] + ">\n")
    xml.write('\t\t</testcase>' + "\n")
xml.write('\t</testsuite>' + "\n")
xml.write('</testsuites>' + "\n")
xml.close()
