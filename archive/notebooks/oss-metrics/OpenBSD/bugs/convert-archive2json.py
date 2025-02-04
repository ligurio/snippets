#!/usr/bin/env python
# encoding=utf-8

"""
Script converts mail archive to a JSON structure,
where each item is a list of mails of a single thread.

    [
        {
            "from_addr": "mail@address",
            "list_name": "openbsd-bugs",
            "msg_date": "19980707234626",
            "msg_link_num": "90222460531614",
            "msg_subject": "kernel/514: Problem with ISA PNP & com ports",
            "msgid": "378958",
            "thread_num": "90224200200037"
        },
        {
            "from_addr": "mail@address",
            "list_name": "openbsd-bugs",
            "msg_date": "19980708011002",
            "msg_link_num": "90222460531615",
            "msg_subject": "Re: kernel/514: Problem with ISA PNP & com ports",
            "msgid": "378959",
            "thread_num": "90224200200037"
        }
    ],

"""

import fnmatch
import itertools
import json
import os
import pprint
import requests
import re
import sys
import subprocess
import time
from lxml.html.clean import Cleaner

reload(sys)
sys.setdefaultencoding('utf8')

MAIL_INDEX = 'all_openbsd-bugs_posts'
URL_TEMPLATE = 'https://marc.info/?l=openbsd-bugs&m=%s&w=2'
RE_CATEGORY = r'>\s?Category:\s+(\w+)'
RE_SYNOPSIS = r'>\s?Synopsis:\s+(.+)'

categories = ["system", "user", "library", "documentation", "kernel"]
architecture = ["alpha", "amd64", "arm", "hppa", "i386",
                "m88k", "mips64", "powerpc", "sh", "sparc",
                "sparc64", "vax"]

def sanitize(dirty_html):
    cleaner = Cleaner(page_structure=True,
                  meta=True,
                  embedded=True,
                  links=True,
                  style=True,
                  processing_instructions=True,
                  inline_style=True,
                  scripts=True,
                  javascript=True,
                  comments=True,
                  frames=True,
                  forms=True,
                  annoying_tags=True,
                  remove_unknown_tags=True,
                  safe_attrs_only=True,
                  safe_attrs=frozenset(['src','color', 'href', 'title', 'class', 'name', 'id']),
                  remove_tags=('span', 'font', 'div', 'p', 'pre', 'br')
                  )

    return cleaner.clean_html(dirty_html)


def parse_mailindex(filename):

    plain_lines = [line.rstrip('\n') for line in open(filename)]
    plain_mails = plain_lines[1:]

    mails = []
    for l in plain_mails:
        line = l.split('\t')
        mail = {'list_name': line[0],
                'msg_date': line[1],
                'msg_link_num': line[2],
                'msgid': line[3],
                'thread_num': line[4],
                'from_addr': line[5],
                'msg_subject': line[6]}
        mails.append(mail)

    return mails


def find_file(filename):

    matches = []
    for root, dirnames, filenames in os.walk('.'):
        for filename in fnmatch.filter(filenames, filename):
            matches.append(os.path.join(root, filename))

    return matches


def get_mail_content(m):

    path = find_file(str(m['msg_link_num']))[0]
    if not os.path.exists(path):
        return ""

    with open(path, 'r') as f:
        content = f.read()

    return content


def json_to_file(json_obj, filename):

    with open(filename, 'w') as bugs:
        json.dump(json_obj, bugs, encoding='latin1',
                sort_keys=True, indent=4, separators=(',', ': '))


def split_by_thread(mails):

    sorted_mails = sorted(mails, key=lambda k: k['thread_num'])
    threads = []
    for key, group in itertools.groupby(sorted_mails, key=lambda x:x['thread_num']):
        threads.append(list(group))

    return threads


def parse_sendbug(body):

    fields = {}
    match = re.match(RE_CATEGORY, body)
    if match:
        category = match.group(1)
        if category in categories:
            fields['category'] = category.lower()
        if category in architecture:
            fields['platform'] = category.lower()

    match = re.match(RE_SYNOPSIS, body)
    if match:
        fields['synopsis'] = match.group(1)

    return fields


def extend_info(threads):

    for thread in threads:
        print "Add more information to the thread %s" % thread[0]['thread_num']
        for idx, m in enumerate(thread):
            m['msg_body'] = sanitize(get_mail_content(m))
            m['msg_url'] = URL_TEMPLATE % m['msg_link_num']
            print "\tAdd body: %s / %s / %s" % (m['msg_subject'], m['from_addr'], m['msg_date'])
            if idx == 0:
                fields = parse_sendbug(m['msg_body'])
                m = dict(m.items() + fields.items())

    return threads


def sort_by_date(threads):

    tds = []
    for i in range(1, len(threads)):
        sorted_thread = sorted(threads[i], key=lambda k: k['msg_date'])
        tds.append(sorted_thread)

    print "Lentgh of list with sorted threads %s" % len(tds)

    bydate = []
    bydate = sorted(tds, key=lambda k: k[0]['msg_date'])
    print "Number of sorted threads %s" % len(bydate)

    return bydate


def main(argv):

    mails = parse_mailindex(MAIL_INDEX)
    pp = pprint.PrettyPrinter(indent=4)
    print "Building a list of mails..."
    print "Number of mails", len(mails)

    threads = sort_by_date(split_by_thread(mails))
    issues = extend_info(threads)
    json_to_file(issues, 'data-full.json')
    print "Number of issues (threads) %s" % len(issues)


if __name__ == "__main__":
    if not main(sys.argv):
        sys.exit(1)
