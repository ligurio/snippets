import xml.etree.ElementTree as ET
import glob
import pprint
import json
import csv

"""
Script convert mail list archive from marc.info
to a JSON struct with mails splitted by threads.
"""

emails = []

archives = glob.glob('data-scraping/data/*.xml')
for doc in archives:
    print doc
    #if doc == 'data-scraping/data/openbsd-bugs2014Bodies.xml':
    #    continue
    #if doc == 'data-scraping/data/openbsd-bugs1999Bodies.xml':
    #    continue

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

pp = pprint.PrettyPrinter(depth=6)
#pp.pprint(emails)

print "Total number of mails:", len(emails)
with open('data3-scraping_.json', 'w') as bugs:
    json.dump(emails, bugs, encoding='latin1',
            sort_keys=True, indent=4, separators=(',', ': '))

#with open('data-scraping/data/openbsd-bugsByEmail.csv', 'rb') as csvfile:
#    emails = csv.reader(csvfile, delimiter=',')
#    for row in emails:
#        print row[2]
