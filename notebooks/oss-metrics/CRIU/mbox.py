#!/usr/bin/python

# Download CRIU mailing list archive

import gzip
import os
import requests

baseurl = "https://lists.openvz.org/pipermail/criu/%s-%s.txt.gz"
months = ["December", "January", "February",
          "March", "April", "May",
          "June", "July", "August",
          "September", "October", "November", ]
mbox_filename = "criu.mbox"


def unpack_file(filename):

    with gzip.open(filename, 'rb') as f:
        print filename
        try:
            file_content = f.read()
            with open(mbox_filename, 'a') as fd:
                fd.write(file_content)
        except IOError:
            print "Failed to unpack %s" % filename


def download_file(url):

    filename = url.split('/')[-1]
    print url, "-->", filename
    r = requests.get(url)
    if r.status_code == 200:
        with open(filename, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)
        return filename


def main():
    for y in range(2013, 2018):
        for m in months:
            # https://lists.openvz.org/pipermail/criu/2014-August.txt.gz
            url = baseurl % (y, m)
            filename = download_file(url)
            if filename is not None and os.path.exists(filename):
                unpack_file(filename)


main()
