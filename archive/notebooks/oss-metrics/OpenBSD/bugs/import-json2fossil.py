#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import re
import sys
import subprocess
import ignorelist

reload(sys)
sys.setdefaultencoding('utf8')

MAX_LENGHT = 100000

openbsd_issues = 'openbsd-issues.json'


def run(command, verbose=False):

    if verbose:
        print("> {0}".format(" ".join(command)))
    p = subprocess.Popen(command, stdout=subprocess.PIPE)

    return p.communicate()[0]


def add_ticket(thread):

    title = thread[0]['subject']
    if not title:
        title = "no subject"
    print "Subject:", title
    print "Date:", thread[0]['timestampReceived']

    tckt_uuid = ""
    for idx, m in enumerate(thread):
        body = m.get('body', None)
        if idx == 0:
            category = m.get('category', "")
            platform = m.get('platform', "")
            version = m.get('system', "")
            msg_url = m.get('url', "")
            contact = "%s (%s)" % (m['senderName'], m['senderEmail'])
            tckt_uuid = create_ticket(
                title, contact, category, version, msg_url, platform)
            print "\tIssue #%s, message id %s" % (tckt_uuid, m['msg_id'])
            append_to_ticket(tckt_uuid, m['body'])
            continue

        append_to_ticket(tckt_uuid, m['body'], comment=True)
        print "\tComment to issue #%s" % tckt_uuid

    return tckt_uuid


def append_to_ticket(tckt_uuid, body, comment=False, user="anonymous"):

    command = ["fossil", "ticket", "--user", user,
               "change", tckt_uuid,
               "mimetype", "text/plain", "--quote"]

    if comment:
        comment_opt = "icomment"
    else:
        comment_opt = "comment"

    if len(str(body)) < MAX_LENGHT:
        cmd = command
        cmd.extend([comment_opt, str(body)])
        run(cmd)
        return

    for idx, chunk in enumerate(chunks(str(body), MAX_LENGHT)):
        cmd = command
        print "\t\tChunk %s" % idx
        if idx == 0:
            cmd.append(comment_opt)
        else:
            cmd.append("+" + comment_opt)

        cmd.append(chunk + "\n")
        run(cmd)


def chunks(s, n):
    """Produce `n`-character chunks from `s`."""

    for start in range(0, len(s), n):
        yield s[start:start + n]


def create_ticket(title, contact, category, version, msg_url, platform, user="anonymous"):

    tckt_uuid = ""
    command = ["fossil", "ticket", "add",
               "--user", user, "title", title.encode("utf-8")]
    out = run(command)
    for match in re.finditer("ticket add succeeded for ([0-9a-f]+)", out):
        tckt_uuid = match.group(1)[:10]

    assert tckt_uuid, "Ticked UUID is not found. Message URL is %s" % msg_url

    command = ["fossil", "ticket", "--user", user,
               "change", tckt_uuid,
               "private_contact", contact,
               "status", "Open",
               "type", category,
               "foundin", version,
               "MARC", msg_url,
               "machine", platform]
    run(command)

    return tckt_uuid


def main(argv):

    issues = json.load(open(openbsd_issues))
    imported_issues = 1

    for issue in issues:
        num_comments = len(issue)
        print "Issue # %s out of %s with %s comment(s)" % (imported_issues,
                                                           len(issues),
                                                           num_comments)
        if issue[0]['msg_id'] in ignorelist.tickets:
            print "Message ID is found in ignorance list, thread is skipped."
            continue

        add_ticket(issue)
        imported_issues = imported_issues + 1


if __name__ == "__main__":
    if not main(sys.argv):
        sys.exit(1)
