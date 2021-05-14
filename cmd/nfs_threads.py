#!/usr/bin/env python3
#
# Copyright (c) 2020-2021 by Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''
Display NFS thread usage info along with NFS I/O context.

Output Sample:
packets   sockets  threads  threads  metadata  read     read  write    write
arrived  enqueued    woken     used     calls  iops  thruput   iops  thruput
  78683       538    78145       57       209  3390  142.5MB   9014  107.0MB
 106114      4527   101587       63        50  4211  166.8MB  13294  133.0MB
 110220      1511   108709       61        10  4347   10.7MB  13767  137.5MB
  80630      4741    75889       62        50  4218  179.4MB   8743  107.9MB
 115463     11400   104063       62        21  4231  179.4MB  15404  150.5MB
'''

import os
import psutil
from signal import signal, SIGINT
import sys
from time import sleep
import datetime
import argparse

PROCFS_NFSD = "/proc/fs/nfsd"
POOL_STATS = "/proc/fs/nfsd/pool_stats"
NFSD_STATS = "/proc/net/rpc/nfsd"

H1 = ['packets', 'sockets', 'threads', 'threads', 'metadata', 'read',
      'read', 'write', 'write']
H2 = ['arrived', 'enqueued', 'woken', 'used', 'calls', 'iops', 'thruput',
      'iops', 'thruput']


def parse_cmdline():
    parser = argparse.ArgumentParser(
        description='Display nfsd thread usage info along with NFS I/O '
        'context')
    parser.add_argument(
        '--interval', type=int, choices=range(1, 31),
        default=5, help='sampling interval in seconds (defaults to 5)')
    return parser.parse_args()


def server_stopped(message=''):
    print("*NFS Server Stopped {}".format(message))


def print_header(header):
    print(' '*19, end='')
    for col in header:
        print('{0:>10}'.format(col), end='')
    print(flush=True)


def pool_stats():
    try:
        with open(POOL_STATS, "r") as file:
            for line in file:
                if not line.startswith("#"):
                    fields = line.split(" ")
                    packets = int(fields[1])
                    enqueued = int(fields[2])
                    woken = int(fields[3])
        return packets, enqueued, woken, None
    except OSError as e:
        server_stopped()
        return 0, 0, 0, e


def nfs_stats():
    try:
        metadata = 0
        readops = 0
        writeops = 0
        with open(NFSD_STATS, "r") as file:
            for line in file:
                if line.startswith("io"):
                    fields = line.split(" ")
                    readbytes = int(fields[1])
                    writebytes = int(fields[2])
                if line.startswith("proc3"):
                    fields = line.split(" ")
                    readops += int(fields[8])
                    writeops += int(fields[9])
                    metadata += int(fields[3])
                    metadata += int(fields[4])
                    metadata += int(fields[5])
                    metadata += int(fields[6])
                    metadata += int(fields[20])
                    metadata += int(fields[21])
                    metadata += int(fields[22])
                if line.startswith("proc4ops"):
                    fields = line.split(" ")
                    readops += int(fields[27])
                    writeops += int(fields[40])
                    metadata += int(fields[5])
                    metadata += int(fields[8])
                    metadata += int(fields[11])
                    metadata += int(fields[17])
                    metadata += int(fields[36])
        return readbytes, writebytes, readops, writeops, metadata, None
    except OSError as e:
        server_stopped()
        return 0, 0, 0, 0, 0, e


def cpu_time(pids):
    "Return a list of time spent on cpu per process in pids"
    ls = []
    for pid in pids:
        try:
            ls.append(psutil.Process(pid).cpu_times().system)
        except psutil.NoSuchProcess as e:
            server_stopped()
            return None, e
    return ls, None


def nfsd_processes():
    "Return a list of nfsd proceses"
    ls = []
    for p in psutil.process_iter(attrs=['name', 'pid', 'uids']):
        if p.info['name'] == "nfsd" and p.info['uids'].real == 0:
            ls.append(p.info['pid'])
    return ls


def print_value(value):
    print('{0:>10}'.format(value), end='')


def print_thruput(value):
    if value > 1073741824:
        print('{0:>8}GB'.format(round(value / 1073741824, 1)), end='')
    elif value > 1048576:
        print('{0:>8}MB'.format(round(value / 1048576, 1)), end='')
    else:
        print('{0:>8}KB'.format(int(value / 1024)), end='')


def print_line(interval):
    lines = 0
    pids = nfsd_processes()

    prevCpuTime, e1 = cpu_time(pids)
    prevPackets, prevEnqueued, prevWoken, e2 = pool_stats()
    prevRB, prevWB, prevRO, prevWO, prevMeta, e3 = nfs_stats()
    if e1 or e2 or e3:
        return

    while(not sleep(interval)):
        nextCpuTime, e1 = cpu_time(pids)
        nextPackets, nextEnqueued, nextWoken, e2 = pool_stats()
        nextRB, nextWB, nextRO, nextWO, nextMeta, e3 = nfs_stats()
        if e1 or e2 or e3:
            return

        #
        # Count threads that used cpu time in this interval
        #
        threads = 0
        for i in range(0, len(prevCpuTime)):
            if not prevCpuTime[i] == nextCpuTime[i]:
                threads += 1
        prevCpuTime = nextCpuTime.copy()

        #
        # The published 'sockets-enqueued' value needs adjustment
        #
        enqueued = (nextEnqueued - prevEnqueued) - (nextWoken - prevWoken)
        if enqueued < 0:
            enqueued = 0

        #
        # For IOPS values less than 10 display with decimal
        #
        readOps = (nextRO - prevRO) / interval
        writeOps = (nextWO - prevWO) / interval
        readOps = int(readOps) if readOps > 9 else round(readOps, 1)
        writeOps = int(writeOps) if writeOps > 9 else round(writeOps, 1)

        #
        # The read/write values are published as a 32-bit
        # value so account for it to wrap in the interval
        #
        if nextRB < prevRB:
            prevRB = 0
        if nextWB < prevWB:
            prevWB = 0

        if lines % 48 == 0:
            print_header(H1)
            print_header(H2)

        print('{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), end='')
        print_value(nextPackets - prevPackets)
        print_value(enqueued)
        print_value(nextWoken - prevWoken)
        print_value(threads)
        print_value(nextMeta - prevMeta)
        print_value(readOps)
        print_thruput((nextRB - prevRB) / interval)
        print_value(writeOps)
        print_thruput((nextWB - prevWB) / interval)
        print(flush=True)

        prevPackets = nextPackets
        prevEnqueued = nextEnqueued
        prevWoken = nextWoken
        prevMeta = nextMeta
        prevRB = nextRB
        prevWB = nextWB
        prevRO = nextRO
        prevWO = nextWO
        lines += 1


def handler(signal_received, frame):
    print(flush=True)
    sys.exit(0)


signal(SIGINT, handler)

arguments = parse_cmdline()

while True:
    if os.path.exists(PROCFS_NFSD):
        print_line(arguments.interval)
    sleep(2)
