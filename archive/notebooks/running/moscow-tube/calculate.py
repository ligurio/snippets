#!/usr/bin/python
# -*- coding: utf-8 -*- 

import argparse
import urllib2
import sys
try:
        import json
except ImportError:
        import simplejson as json
from collections import defaultdict

json_time_source="stations-time.json"
json_coord_source="stations-coord.json"

def calculate():
        json_data=open(json_time_source).read()
        time_data = json.loads(json_data)

        links = time_data[0]["linkCount"]
        for l in range(1, links):
            fromStation = time_data[0]["links"][str(l)]["fromStationId"]
            toStation = time_data[0]["links"][str(l)]["toStationId"]
            toline = time_data[0]["stations"][str(toStation)]["lineId"]
            fromline = time_data[0]["stations"][str(fromStation)]["lineId"]
            tolinename = time_data[0]["lines"][str(toline)]["name"]
            fromlinename = time_data[0]["lines"][str(fromline)]["name"]
            nameFromStation = time_data[0]["stations"][str(fromStation)]["name"]
            nameToStation = time_data[0]["stations"][str(toStation)]["name"]
            time = time_data[0]["links"][str(l)]["weightTime"]

            flat = get_coord(fromlinename, nameFromStation, "lat")
            flon = get_coord(fromlinename, nameFromStation, "long")
            tlat = get_coord(tolinename, nameToStation, "lat")
            tlon = get_coord(tolinename, nameToStation, "long")

            permalink = "http://www.yournavigation.org/?flat=" + flat + \
            "flon=" + flon + "&tlat=" + tlat + "&tlon=" + tlon + "&v=foot&shortest=1&layer=mapnik"

            url_metro = "http://metro.yandex.ru/moscow?from=" + str(fromStation) + "&to=" + str(toStation) + "&route=0"

            print "%s, %s, %s, %s, %d, %s, %s, %s" % (fromlinename, tolinename, \
            nameFromStation, nameToStation, time, url_metro, get_distance(flat, flon, tlat, tlon), permalink)

def get_coord(lnname, stname, coordinate):
        json_data=open(json_coord_source).read()
        coord_data = json.loads(json_data)
        for jline in coord_data:
            if jline["line"] == lnname:
               for station in jline["stations"]:
                   if station["station"] == stname:
                      return station[coordinate]

def get_distance(flat, flon, tlat, tlon):
        url = "http://www.yournavigation.org/api/1.0/gosmore.php?format=geojson&flat=" \
        + flat + "&flon=" + flon + "&tlat=" + tlat + "&tlon=" + tlon + "&v=foot&shortest=1&layer=mapnik"
        geodata = json.load(urllib2.urlopen(url))
        return geodata["properties"]["distance"]

if len(sys.argv) > 1:
        sys.exit(1)

calculate()
