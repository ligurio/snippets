#!/usr/bin/env python

import json
import pprint
import requests
import time

GH_ISSUE_URL = 'https://api.github.com/repos/%s/%s/issues'
GH_PROFILE_URL = 'https://api.github.com/users/%s'
GH_COMMENT_URL = 'https://api.github.com/repos/%s/%s/issues/%s/comments'

USERNAME = 'ligurio'
PASSWORD = 'TOKEN'

REPO_OWNER = 'ligurio'
REPO_NAME = 'testrepo'


def post_github_issue(title, body=None, milestone=None, labels=None):

    url = GH_ISSUE_URL % (REPO_OWNER, REPO_NAME)
    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)

    issue = {'title': title}
    if body:
        issue['body'] = str("```\n" + body + "\n```")

    while True:
        try:
            r = session.post(url, json.dumps(issue, encoding='latin1'))
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            wait_sec = time_rate_limit_reset()
            print "retry after %s sec" % wait_sec
            #time.sleep(wait_sec)
            time.sleep(60)
            continue
        break

    return json.loads(r.text)


def get_current_rate_limits():

    url = GH_PROFILE_URL % REPO_OWNER
    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)
    while True:
        try:
            r = session.get(url)
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            wait_sec = time_rate_limit_reset()
            print "retry after %s sec" % wait_sec
            #time.sleep(wait_sec)
            time.sleep(60)
            continue
        break

    return {'Remaining': r.headers['X-RateLimit-Remaining'],
            'Limit': r.headers['X-RateLimit-Limit'],
            'Reset': r.headers['X-RateLimit-Reset']}


def time_rate_limit_reset():

    limits = get_current_rate_limits()
    curtime = int(time.time())
    diff = int(limits['Reset']) - curtime
    if diff < 0:
        sec = 0
    else:
        sec = diff

    return sec


def post_issue_from_thread(thread):

    title = thread[0].get('msg_subject')
    if not title:
        title = "no subject"

    ret = post_github_issue(title=title, body=thread[0]['body'])
    id = ret.get('number')
    print "\tIssue #%s %s" % (id, ret.get('url'))

    if len(thread) != 1:
        for i in range(len(thread)):
            if i == 0:
                continue
            post_issue_comment(thread[i]['body'], id)
            print "\tComment to issue #%s" % id

    return ret


def post_issue_comment(comment, id):

    url = GH_COMMENT_URL % (REPO_OWNER, REPO_NAME, id)
    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)
    cmnt = "```\n" + comment + "\n```"
    comment_json = {'body': str(cmnt)}

    while True:
        try:
            r = session.post(url, json.dumps(comment_json, encoding='latin1'))
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            wait_sec = time_rate_limit_reset()
            print "retry after %s sec" % wait_sec
            time.sleep(60)
            #time.sleep(wait_sec)
            #pp.pprint(comment_json)
            continue
        break


issues = json.load(open('data1.json'))
total_issues = len(issues)
imported_issues = 0

for issue in issues:
    len_thread = len(issue)
    imported_issues = imported_issues + 1
    print "Post (%s/%s) issue from thread %s (%s mails)" % (imported_issues,
                                                            total_issues,
                                                            issue[0]['thread_num'],
                                                            len_thread)
    post_issue_from_thread(issue)
