#!/usr/bin/env python3
#
# Copyright (c) 2020 by Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''
Display NFS thread usage info along with NFS I/O context.

Output Sample:

 packets  sockets threads threads metadata  read    read  write   write
 arrived enqueued   woken   used     calls  iops thruput   iops thruput
    4589        0    4589     25        16   273   3.6MB    212   2.6MB
    4735        0    4735      8         1   287   3.8MB    212   2.7MB
    4693        0    4693     10         0   280   3.7MB    216   2.7MB
    4625        0    4625     15         0   278   3.7MB    212   2.6MB
    4687        0    4687      7         1   285   3.8MB    210   2.6MB
    4701        0    4701     12         0   285   3.8MB    215   2.7MB
'''

import psutil
from signal import signal, SIGINT
import sys
from time import sleep

POOL_STATS = "/proc/fs/nfsd/pool_stats"
NFSD_STATS = "/proc/net/rpc/nfsd"

H1 = ['packets', 'sockets', 'threads', 'threads', 'metadata', 'read',
      'read', 'write', 'write']
H2 = ['arrived', 'enqueued', 'woken', 'used', 'calls', 'iops', 'thruput',
      'iops', 'thruput']

INTERVAL = 5


def server_stopped(message=''):
    print("NFS Server Stopped {}".format(message))
    sys.exit()


def print_header(header):
    for col in header:
        print('{0:>10}'.format(col), end='')
    print()


def pool_stats():
    try:
        with open(POOL_STATS, "r") as file:
            for line in file:
                if not line.startswith("#"):
                    fields = line.split(" ")
                    packets = int(fields[1])
                    enqueued = int(fields[2])
                    woken = int(fields[3])
                    timedout = int(fields[4])
        return packets, enqueued, woken, timedout
    except OSError:
        server_stopped()


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
        return readbytes, writebytes, readops, writeops, metadata
    except OSError:
        server_stopped()


def context_switches(pids):
    "Return a list of context switches per process in pids"
    ls = []
    for pid in pids:
        try:
            pctxsw = psutil.Process(pid).num_ctx_switches()
            ls.append(pctxsw.voluntary + pctxsw.involuntary)
        except psutil.NoSuchProcess:
            server_stopped()
    return ls


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


def print_line():
    pids = nfsd_processes()

    prevSwitches = context_switches(pids)
    prevPackets, prevEnqueued, prevWoken, prevTimedout = pool_stats()
    prevRB, prevWB, prevRO, prevWO, prevMeta = nfs_stats()

    while(not sleep(INTERVAL)):
        nextSwitches = context_switches(pids)
        nextPackets, nextEnqueued, nextWoken, nextTimedout = pool_stats()
        nextRB, nextWB, nextRO, nextWO, nextMeta = nfs_stats()

        threads = 0
        for i in range(0, len(prevSwitches)):
            if not prevSwitches[i] == nextSwitches[i]:
                threads += 1
        threads -= nextTimedout - prevTimedout
        prevSwitches = nextSwitches.copy()

        #
        # The published 'sockets-enqueued' value needs adjustment
        #
        enqueued = (nextEnqueued - prevEnqueued) - (nextWoken - prevWoken)

        #
        # For IOPS values less than 10 display with decimal
        #
        readOps = (nextRO - prevRO) / INTERVAL
        writeOps = (nextWO - prevWO) / INTERVAL
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

        print_value(nextPackets - prevPackets)
        print_value(enqueued)
        print_value(nextWoken - prevWoken)
        print_value(threads)
        print_value(nextMeta - prevMeta)
        print_value(readOps)
        print_thruput((nextRB - prevRB) / INTERVAL)
        print_value(writeOps)
        print_thruput((nextWB - prevWB) / INTERVAL)
        print()

        prevPackets = nextPackets
        prevEnqueued = nextEnqueued
        prevWoken = nextWoken
        prevTimedout = nextTimedout
        prevMeta = nextMeta
        prevRB = nextRB
        prevWB = nextWB
        prevRO = nextRO
        prevWO = nextWO


def handler(signal_received, frame):
    print()
    sys.exit(0)


signal(SIGINT, handler)

print_header(H1)
print_header(H2)
print_line()
