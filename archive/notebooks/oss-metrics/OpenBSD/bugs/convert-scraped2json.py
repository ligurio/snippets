#!/usr/local/bin/python

# -*- coding: utf-8 -*- 

import csv
import re
import pprint
import sys
import json
import xml.etree.ElementTree as ET
import glob

reload(sys)
sys.setdefaultencoding('utf8')

RE_MSG_LINK_NUM = r'.+&m=([0-9]+)&w=2'
RE_CATEGORY = r'>\s?Category:\s+(\w+)'
RE_PLATFORM = r'>\s?Machine:\s+(\w+)'
RE_SYNOPSIS = r'>\s?Synopsis:\s+(.+)'
RE_SYSTEM = r'\s?System\s+:\s+OpenBSD\s+(.+)'

sendbug_categories = ["system", "user", "library", "documentation", "kernel"]
sendbug_platforms = ["alpha", "amd64", "arm", "hppa", "i386",
                     "m88k", "mips64", "powerpc", "sh", "sparc",
                     "sparc64", "vax"]

csv_file = 'data/scrapped/openbsd-bugsByEmail.csv'
xml_files = 'data/scrapped/*.xml'
csv_json = 'scraping-processed-csv.json'
xml_json = 'scraping-processed-xml.json'

pp = pprint.PrettyPrinter(indent=4)

def find_reply(index, mail):

    for m in index:
        if mail['msg_id'] == m['msg_replyto']:
            return m

    return None


def extract_msg_id(msg_url):

        match = re.match(RE_MSG_LINK_NUM, msg_url)
        msg_id = ''
        if match:
            msg_id = match.group(1)
        else:
            msg_id = None

        return msg_id


def read_xml(xml_files):

    emails = []
    archives = glob.glob(xml_files)
    for doc in archives:
        print doc
        tree = ET.parse(doc)
        root = tree.getroot()
        for email in root.findall('email'):
            msg = {}
            msg['msgid'] = email.find('emailId').text
            msg['msg_subject'] = email.find('subject').text
            msg['from_name'] = email.find('senderName').text
            msg['from_addr'] = email.find('senderEmail').text
            msg['msg_date'] = email.find('timestampReceived').text
            msg['body'] = email.find('body').text
            msg['threadnum'] = email.find('body').text
            emails.append(msg)
    
    return emails


def read_csv(csv_file):

    # CSV index
    # Format: emailId,senderName,senderEmail,timestampReceived,subject,url,replyto

    index = []
    with open(csv_file, 'rb') as csvfile:
        emails = csv.reader(csvfile, delimiter=',')
        next(emails, None)  # skip the headers

        for row in emails:

            msg_url = row[5]
            msg_id = extract_msg_id(msg_url)

            replyto_url = row[6]
            msg_replyto = extract_msg_id(replyto_url)

            mail = { 'emailId': row[0],
                     'senderName': row[1],
                     'senderEmail': row[2],
                     'timestampReceived': row[3],
                     'subject': row[4],
                     'url': row[5],
                     'replyto': row[6],
                     'msg_id': msg_id,
                     'msg_replyto': msg_replyto }
            index.append(mail)

    return index


def print_thread(thread):

    indent = ''
    for m in thread:
        print indent, m['subject'], m['senderEmail'], m['timestampReceived']
        indent = indent + "\t"

    print "\n=============================================================\n"


def group_by_threads(index):

    threads = []
    for m in index:
        thread = []
        if m['replyto'] == "NA":
            thread.append(m)
            threads.append(thread)

    print "Number of NA messages: ", len(threads)

    for thread in threads:
        mail = thread[0]
        while True:
            reply = find_reply(index, mail)
            if reply:
                thread.append(reply)
                mail = reply
                continue
            else:
                break

        print_thread(thread)

    return threads


def add_bodies(mails, thread):

    for comment in thread:
        body = ''
        for m in mails:
            if m['msgid'] == comment['emailId']:
                body = m['body']
        comment['body'] = body

    return thread


def write_to_file(json_struct, filename):

    print "JSON struct written to %s" % filename

    with open(filename, 'w') as f:
        json.dump(json_struct, f, encoding='latin1',
                sort_keys=True, indent=4, separators=(',', ': '))


def sort_threads_by_date(threads):

    bydate = []
    bydate = sorted(threads, key=lambda k: k[0]['timestampReceived'])
    print "Number of sorted threads %s" % len(bydate)

    return bydate


def extract_field(regex, body):

    field = ""
    match = re.search(regex, str(body))
    if match:
        field = match.group(1).lower()

    return field


def merge_two_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z


def parse_senbug(body):

    sendbug = {}

    platform = ""
    system = ""
    category = ""
    match = extract_field(RE_CATEGORY, body)
    if match in sendbug_categories:
	category = match
    if match in sendbug_platforms:
	platform = match

    if not platform:
	platform = extract_field(RE_PLATFORM, body)
    
    sendbug['platform'] = platform
    sendbug['category'] = category
    sendbug['system'] = extract_field(RE_SYSTEM, body)

    return sendbug


def main():

    #mail_index = read_csv(csv_file)
    #threads = group_by_threads(mail_index)
    #print "Total number of threads in a CSV index: ", len(threads)

    #emails = read_xml(xml_files)
    #print "Total number of mails in XML archive:", len(emails)

    #write_to_file(threads, csv_json)
    #write_to_file(emails, xml_json)

    emails = json.load(open(xml_json))
    threads = json.load(open(csv_json))
    threads = sort_threads_by_date(threads)
    empty_messages = []

    issues = []
    for t in threads:
        print t[0]['msg_id'], t[0]['subject']
        issue = add_bodies(emails, t)
        issues.append(issue)

        if not t[0]['body']:
            empty_messages.append(t[0]['msg_id'])
            continue

	t[0] = merge_two_dicts(t[0], parse_senbug(t[0]['body']))

    write_to_file(issues, 'openbsd-issues.json')
    print "ID's of messages with empty body", empty_messages

main()
