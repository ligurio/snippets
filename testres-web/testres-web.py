#!/usr/bin/env python

import argparse
import subprocess
import os
import time
import sys
import logging
import webbrowser

DEFAULT_ADDRESS = "127.0.0.1"
DEFAULT_PORT = "8080"
DEFAULT_CGI_PATTERN = "*.cgi"

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

def run_httpd(cmd_line):
    logging.info("Running http server: %s" % cmd_line)
    proc = subprocess.Popen(cmd_line.split(' '),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            shell=True)
    return proc.pid

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpd_bin", help="http server binary")
    parser.add_argument("--port", help="port")
    args = parser.parse_args()

    if args.httpd_bin:
        logging.warning(args.httpd_bin)

    script_name = sys.argv[0]
    cwd = os.getcwd()
    thttpd_cmd = "thttpd -p %s -c %s -d %s" % (DEFAULT_PORT, DEFAULT_CGI_PATTERN, cwd)
    browser_url = 'http://%s:%s' % (DEFAULT_ADDRESS, DEFAULT_PORT)

    try:
        pid = run_httpd(thttpd_cmd)
        webbrowser.open(browser_url, new = 2)
    except KeyboardInterrupt:
        os.terminate(pid)

if __name__ == "__main__":
    main()
