# -*- coding: utf-8 -*-
# Source: https://yurichev.com/blog/fuzzy_string/files/get_typos.py
# Python 2.7

from lxml import etree
from sets import Set
import sys
import time
import re
import os
import frobenoid
import Levenshtein


def wikipedia_main_namespace(title):
    if title.startswith("Wikipedia:"):
        return False
    if title.startswith("Wikipedia talk:"):
        return False
    if title.startswith("User:"):
        return False
    if title.startswith("User talk:"):
        return False
    if title.startswith("Category:"):
        return False
    if title.startswith("Category talk:"):
        return False
    if title.startswith("Talk:"):
        return False
    if title.startswith("File:"):
        return False
    if title.startswith("File talk:"):
        return False
    if title.startswith("Template:"):
        return False
    if title.startswith("Template talk:"):
        return False
    if title.startswith("Portal:"):
        return False
    if title.startswith("Special:"):
        return False
    if title.startswith(":"):
        return False
    return True


def process_file(fname, words_stat):
    current_tags = []
    tmp = "{http://www.mediawiki.org/xml/export-0.10/}"
    namespaces = []
    cur_title = ""

    context = etree.iterparse(fname, events=(
        "start", "end", "start-ns", "end-ns"))
    for event, elem in context:
        if event == "start-ns":
            namespaces.insert(0, elem)

        if event == "end-ns":
            namespaces.pop(0)

        if event == "start":
            current_tags.append(elem.tag)

        if event == "end":
            if current_tags[-1] != elem.tag:
                raise AssertionError
            current_tags.pop()

            if elem.tag == tmp+"title":
                cur_title = elem.text

            if elem.tag == tmp+"text":
                if wikipedia_main_namespace(cur_title) and elem.text != None:  # FIXME
                    # this is text in main namespace
                    for x in re.split('\s+', elem.text):
                        l = unicode(x.lower())
                        if len(l) > 5 and frobenoid.str_is_cyr_utf_8(l):
                            # if len(l)>5 and frobenoid.str_is_latin(l):
                            frobenoid.inc_value_in_dict(words_stat, l)

            if elem.tag == tmp+"page":
                pass
            elem.clear()


words_stat = {}

i = 1
args = len(sys.argv)
while i < args:
    fname = sys.argv[i]
    sys.stderr.write("parsing "+fname+"...\n")
    process_file(fname, words_stat)
    sys.stderr.write(fname+" parsed\n")
    i = i+1

if i == 1:
    print("no files at input")
    print("usage: enwiki* > typos")
    exit(0)

words_stat_len = len(words_stat)
dictionary_word_threshold = words_stat_len/500
typo_threshold = dictionary_word_threshold/100  # 1%

print("words_stat_len=", words_stat_len)
print("dictionary_word_threshold=", dictionary_word_threshold)
print("typo_threshold=", typo_threshold)

probably_correct_words = filter(
    lambda x: words_stat[x] > dictionary_word_threshold, words_stat)
print("len(probably_correct_words)=", len(probably_correct_words))

words_to_check_unsorted = filter(
    lambda x: words_stat[x] < typo_threshold, words_stat)
words_to_check = sorted(words_to_check_unsorted,
                        key=lambda x: words_stat[x], reverse=False)
print("len(words_to_check)=", len(words_to_check))

for w in words_to_check:
    suggestions = []
    for wd in probably_correct_words:
        dist = Levenshtein.distance(w, wd)
        if dist == 1:
            # if 1 <= dist <= 2:
            suggestions.append(wd)
    if len(suggestions) > 0:
        print("typo?", w, "("+str(words_stat[w])+") suggestions=", suggestions)
