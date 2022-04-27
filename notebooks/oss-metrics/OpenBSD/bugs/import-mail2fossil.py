#!/usr/bin/env python
# encoding=utf-8

"""Email to Fossil SCM gateway.

Reads RFC2822 email message from stdin and adds it to the specified Fossil SCM
database.  Message-ID to ticket hash map is stored in a cache file located in
~/.local/share/mail2fossil.json. Duplicate messages are ignored, messages with
no Message-ID header are also ignored (in a draft from maildir is fed, etc).

Example usage:

    > cat message.eml | mail2fossil -b http://bugs.example.com \
      -R ~/fossil/bugs.fossil

Now, when somebody emails a certain address, this script is invoked, the
message is parsed, data is extracted, a new ticket is added and pushed to the
parent repository (if any), then a confirmation email built with the above
template is emailed back to the reporter.

Example config for fdm MDA (mail2fossil-bugs is a script which invokes
mail2fossil with required options):

    action "fossil" pipe "mail2fossil-bugs"
    match "To:.*bugs@example.com" in headers action "fossil" continue

To use with Postfix or other aliases-aware MDA, add something like this
to your /etc/aliases (lines may not be wrapped in aliases, wrapping is only
added here for readability):

    bugs: "|/usr/local/bin/mail2fossil -b http://bugs.example.com
        -R /var/lib/fossil/bugs.fossil"
"""

from __future__ import print_function

import email
import email.parser
import json
from optparse import OptionParser
import os
import re
import subprocess
import sys


__autor__ = "Sergey Bronnikov"
__email__ = "sergeyb@bronevichok.ru"

CACHE_PATH = "~/.local/share/mail2fossil.json"

class Cache(dict):
    def __init__(self):
        self.fn = os.path.expanduser(CACHE_PATH)
        self.load()

    def load(self):
        if os.path.exists(self.fn):
            with open(self.fn, "rb") as f:
                self.update(json.loads(f.read()))

    def save(self):
        with open(self.fn, "wb") as f:
            f.write(json.dumps(self))


class Fossil(object):
    def __init__(self, path):
        self.path = path


    def __repr__(self):
        return "<Fossil repo={0}>".format(self.path)


    def get_users(self):
        """Returns a dictionary of repo users and their emails."""
        out = self.run(["fossil", "user", "-R", self.path, "list"])

        users = []
        for line in out.strip().split("\n"):
            if not line.strip():  # skip empty lines, if any
                continue
            parts = re.split("\s+", line.strip(), 1)
            if len(parts) != 2:
                parts.append(None)
            users.append(parts)

        return dict(users)


    def get_user_by_email(self, email):
        for k, v in self.get_users().items():
            if k == email or v == email:
                return k
        return "anonymous"


    def add_ticket(self, summary, description, email):
        command = ["fossil", "ticket",
            "-R", self.path,
            "--user", self.get_user_by_email(email),
            "add",
            "-q",
            "title", summary.encode("utf-8"),
            "comment", description.encode("utf-8"),
            "status", "Open",
            "type", ""]
        out = self.run(command)
        for match in re.finditer("ticket add succeeded for ([0-9a-f]+)", out):
            self.push()
            return match.group(1)[:10]


    def push(self):
        self.run(["fossil", "push", "-R", self.path], verbose=True)


    def run(self, command, verbose=False):
        if verbose:
            print("> {0}".format(" ".join(command)),
                file=sys.stderr)
        p = subprocess.Popen(command, stdout=subprocess.PIPE)
        return p.communicate()[0]


def parse_message(raw_msg):
    p = email.parser.Parser()
    msg = p.parsestr(raw_msg)

    parsed = {}
    parsed["Date"] = msg["Date"]
    parsed["id"] = msg["Message-Id"]
    parsed["subject"] = msg["Subject"]
    parsed["from"] = email.utils.parseaddr(msg["From"])[1]
    print(parsed)

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/alternative":
                continue

            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True) \
                    .decode(part.get_content_charset())
                parsed["body"] = body
    else:
        parsed["body"] = msg.get_payload(decode=True)

    # FIXME: add parsing of sendbug fields

    return parsed


def handle_message(msg):
    f = Fossil(options.repo)

    uuid = f.add_ticket(msg["subject"], msg["body"], msg["from"])
    if not uuid:
        print("Error adding a ticket.", file=sys.stderr)
        sys.exit(1)

    ticket_url = "{0}/tktview?name={1}".format(
        options.base_url, uuid)

    print("New ticket created: {0}.".format(ticket_url, msg["from"]), file=sys.stderr)

    return uuid


def main(argv):
    parser = OptionParser()
    parser.add_option("-b", "--base", dest="base_url",
        help="specify base Fossil URL", metavar="URL")
    parser.add_option("-R", "--repository", dest="repo",
        help="Fossil repository to add ticket to",
        metavar="FILE")

    global options, args
    (options, args) = parser.parse_args()

    if not options.base_url:
        parser.error("Base URL not given.")
    elif not options.repo:
        parser.error("Repository path not given.")

    if len(argv) < 2:
        print("Usage: {0} repository".format(argv[0]))
        return False

    msg = parse_message(sys.stdin.read())

    if not msg:
        print("Unable to parse message.", file=sys.stderr)
        return False
    elif not msg["id"]:
        print("No Message-Id, ignoring.", file=sys.stderr)
        return False

    cache = Cache()
    if msg["id"] in cache:
        print("Message {0} already was processed.".format(
            msg["id"]), file=sys.stderr)
        return True

    uuid = handle_message(msg)

    cache[msg["id"]] = uuid
    cache.save()

    return True


if __name__ == "__main__":
    if not main(sys.argv):
        sys.exit(1)
