#!/usr/bin/env python

# python3 -m http.server --bind localhost --cgi 8000

import argparse
import subprocess
import os
import time
import sys
import logging
import webbrowser
from http.server import CGIHTTPRequestHandler
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_ADDRESS = "127.0.0.1"
DEFAULT_PORT = "8080"
DEFAULT_CGI_PATTERN = "*.cgi"

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

def run_thttpd(port, cgi_pattern, webroot):
    thttpd_cmd = "thttpd -p %s -c %s -d %s" % (port, cgi_pattern, webroot)
    logging.info("Running thttpd server: %s" % cmd_line)
    proc = subprocess.Popen(cmd_line.split(' '),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            shell=True)
    return proc.pid

def run_python_httpd(port, cgi_pattern, webroot):
    logging.info("Running Python http server")
    server_address = ('', int(port))
    handler = CGIHTTPRequestHandler
    handler.cgi_directories = ['/cgi']
    httpd = HTTPServer(server_address, handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.socket.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", help="address")
    parser.add_argument("--port", help="port")
    parser.add_argument("--webroot", help="webroot")
    args = parser.parse_args()

    if not args.port:
        port = DEFAULT_PORT
    else:
        port = args.port

    if not args.address:
        address = DEFAULT_ADDRESS
    else:
        address = args.address

    if not args.webroot:
        webroot = os.getcwd()
    else:
        webroot = args.webroot

    logging.info("Address %s, port %s, webroot %s" % (address, port, webroot))
    # browser_url = 'http://%s:%s' % (address, port)
    try:
        # pid = run_thttpd(port, DEFAULT_CGI_PATTERN, webroot)
        run_python_httpd(port, DEFAULT_CGI_PATTERN, webroot)
        webbrowser.open(browser_url, new = 2)
    except KeyboardInterrupt:
        # os.terminate(pid)
        pass

if __name__ == "__main__":
    main()
