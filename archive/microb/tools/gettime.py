#!/usr/bin/env python

# http://pubs.opengroup.org/onlinepubs/9699919799/functions/clock_getres.html
# http://www.ntp.org/ntpfaq/NTP-s-sw-clocks-quality.htm
# PEP 418 https://www.python.org/dev/peps/pep-0418/
# https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_MRG/2/html/Realtime_Reference_Guide/chap-Timestamping.html

# Monitoring time drift: ntpdate -d 10.64.16.3
# TODO: use time.clock_gettime_ns(clk_id) and time.time_ns() (Python 3.7+)

from contextlib import closing
from socket import socket, AF_INET, SOCK_DGRAM
import sys
import struct
import time
import os

NTP_PACKET_FORMAT = "!12I"
NTP_DELTA = 2208988800  # 1970-01-01 00:00:00
NTP_QUERY = str.encode('\x1b' + 47 * '\0')
# Kasperky Lab: 10.64.16.3,10.64.16.4,10.64.32.3,10.64.64.3,10.70.8.3
NTP_SERVER = "10.64.16.3"

TIME_PRECISION = 2
TIME_FORMAT = "%H:%M:%S"
SLEEP_TIME = 2


def set_cpu_affinity(mask):
    pid = os.getpid()
    if sys.platform == 'linux':
        print("Get CPU affinity", os.sched_getaffinity(pid))
        os.sched_setaffinity(pid, mask)
        print("Get CPU affinity", os.sched_getaffinity(pid))
    else:
        import psutil
        p = psutil.Process(pid)
        print("Get CPU affintiy", p.cpu_affinity)
        p.cpu_affinity = [0]
        print("Get CPU affintiy", p.cpu_affinity)


def get_ntp_time(host=NTP_SERVER, port=123):
    with closing(socket(AF_INET, SOCK_DGRAM)) as s:
        s.sendto(NTP_QUERY, (host, port))
        msg, address = s.recvfrom(1024)
    unpacked = struct.unpack(NTP_PACKET_FORMAT,
                             msg[0:struct.calcsize(NTP_PACKET_FORMAT)])
    return unpacked[10] + float(unpacked[11]) / 2 ** 32 - NTP_DELTA


def print_time(clock, t, diff):
    if diff > 0:
        diff_str = "+{0}".format(diff)
    elif diff <= 0:
        diff_str = "{0}".format(diff)

    time_str = time.strftime(TIME_FORMAT, time.localtime(t))
    print('{0:<14} {1:>10} {2:>14}'.format(
        clock, time_str, diff_str))


if __name__ == "__main__":

    if sys.version_info[0] < 3:
        raise Exception("Must be using Python 3")

    set_cpu_affinity([0])

    print("-" * 60)
    print("{0:<14} {1:>10} {2:>14}".format(
        "Clock source", "Time", "Diff (sec)"))
    print("-" * 60)
    current = time.monotonic()
    while True:
        ntp_time = int(get_ntp_time())
        if sys.platform == 'linux':
            real_time = time.clock_gettime(time.CLOCK_REALTIME)
        else:
            real_time = time.time()
        real_diff = round(ntp_time - real_time, TIME_PRECISION)

        print_time("NTP({0})".format(NTP_SERVER), ntp_time, 0)
        print_time("CLOCK_REALTIME ", real_time, real_diff)
        print()

        previous = current
        current = time.monotonic()
        if current <= previous:
            print("Time ran backward:")
            print("\tcurrent: {0}".format(current))
            print("\tprevious: {0}".format(previous))
            print("\tInterval is {0} seconds".format(SLEEP_TIME))

        time.sleep(SLEEP_TIME)
