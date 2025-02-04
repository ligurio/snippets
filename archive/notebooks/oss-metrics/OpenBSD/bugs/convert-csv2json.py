import csv
import re
import pprint
import json

# emailId,senderName,senderEmail,timestampReceived,subject,url,replyto

MSG_LINK_NUM_RE=r'.+&m=([0-9]+)&w=2'

def find_reply(index, mail):

    for m in index:
        if mail['msg_id'] == m['msg_replyto']:
            return m

    return None


index = []
with open('data-scraping/data/openbsd-bugsByEmail.csv', 'rb') as csvfile:
    emails = csv.reader(csvfile, delimiter=',')
    for row in emails:
        match = re.match(MSG_LINK_NUM_RE, row[5])
        msg_id = ''
        if match:
            msg_id = match.group(1)
        else:
            msg_id = None

        match = re.match(MSG_LINK_NUM_RE, row[6])
        msg_replyto = ''
        if match:
            msg_replyto = match.group(1)
        else:
            msg_replyto = None

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

threads = []
for m in index:
    thread = []
    if m['replyto'] == "NA":
        thread.append(m)
        threads.append(thread)

pp = pprint.PrettyPrinter(indent=4)
print "Number of NA messages: ", len(threads)

for thread in threads:
    mail = thread[0]
    print "Latest message in a thread: ", mail['emailId']
    while True:
        reply = find_reply(index, mail)
        if reply:
            thread.append(reply)
            mail = reply
            continue
        else:
            break
    pp.pprint(thread)

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(threads)
print "Number of threads: ", len(threads)

with open('data4-index.json', 'w') as bugs:
    json.dump(threads, bugs, encoding='latin1',
            sort_keys=True, indent=4, separators=(',', ': '))
