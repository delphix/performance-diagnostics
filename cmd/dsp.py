#!/usr/bin/python3

import argparse
import threading
import subprocess
import sys
import time

# active_cmd_threshold is used to filter out nexus that are mostly idle.
# It's the number of commands that must complete in an interval to display
# an output line.
active_cmd_threshold = 5

jmxtool = "/opt/delphix/server/bin/jmxtool"
disp_lock = threading.Lock()
aggr_lock = threading.Lock()
aggr_data = {'raw_tput': 0, 'compress_tput': 0, 'count': 0}

NS_TO_US = 1000


#
# dsp.py
#
# dsp.py is a script for monitoring the performance of Delphix workflows that
# leverage DSP(Delphix Session Protocol).
# Currently, as of 5.1, Replication, SnapSync, V2P(export), UEM, all leverage
# DSP. This script leverages the raw stats provided by the various
# 'jmxtool dsp <command>' commands to extrace and parse the relevant
# statistics.
# The script can be invoked as follows:
#
# ./dsp.py [nexus id]
#
# Without the optional [nexus id], dsp.py will list all the available nexi
# and allow a user selection.

#
# Note: As of Delphix 5.1, the replication workflow leverages the DataMover
# service. Previously a single nexus was used for both control and data
# streams. In 5.1, there are two separate nexi, with the DataMover representing
# the 'data' portion.
# This nexus should be chosen when trying to identify performance
# bottlenecks in the data transfer phase.
#

#
# getnexus() - parse arg(if supplied) and validate user selection of nexus
#


def getnexus():
    menu = {}
    nexus = None
    cnt = 0

    # check if user specified nexus on command line
    if (len(sys.argv) > 1):
        nexus = sys.argv[1]

    # get a list of client and server nexi that are currently active
    stri_c = subprocess.Popen([jmxtool, 'dsp', 'list-clients'],
                              stdout=subprocess.PIPE,
                              text=True).communicate()[0].splitlines()

    stri_s = subprocess.Popen([jmxtool, 'dsp', 'server-clients'],
                              stdout=subprocess.PIPE,
                              text=True).communicate()[0].splitlines()

    for line in stri_c + stri_s:
        item = str(line)
        menu[item] = [item]
        if ('Replication' in item):
            repl_id = item.rsplit('-', 1)[1]
            try:
                menu[repl_id].append(item)
            except KeyError:
                menu[repl_id] = [item]

    if (len(menu) == 0):
        return (None)

    # verify supplied nexus exists
    if (nexus is not None) and (nexus in menu):
        return (menu[nexus])

    # display menu for user to select nexus
    # TODO - change this to include the IP address or some other
    # TODO - defining characteristic
    key_list = list(menu)
    for line in key_list:
        print(str(cnt) + " :  " + line)
        cnt = cnt + 1
    option = input("Select Nexus >")

    return (menu[key_list[int(option)]])


def printnexus(nexus):
    show_nexus = subprocess.Popen([jmxtool, 'dsp', 'show-nexus', nexus],
                                  stdout=subprocess.PIPE,
                                  text=True).communicate()[0]
    print(show_nexus)
    return


def aggr_thread(tbd):
    global aggr_data  # noqa: F824
    while True:
        time.sleep(2 * interval)
        aggr_lock.acquire()
        if (aggr_data['count']):
            throughput = int(aggr_data['raw_tput'] / aggr_data['count'])
            cthroughput = int(aggr_data['compress_tput'] / aggr_data['count'])
        aggr_lock.release()
        my_time = time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())
        print('{:<25} {:<15} {:35} {:>10} {:>10}'.format(my_time,
                                                         'Aggregate',
                                                         '',
                                                         throughput,
                                                         cthroughput))


#
# dsp_server() - dump dsp server side statistics for given nexus
#


def dsp_server(nexus, aggr=False):
    global NS_TO_US  # noqa: F824
    dict = {}
    prev_dict = {}

    # determine which side of the connection is the DSP server
    # replication - replication target DE (show-peer-stats)
    # snapsync    - DE (show-stats)
    # export(V2P) - DE (show-peer-stats) - the target host is the DSP client
    #                                      but receives data as the server
    #               DE acts as the DSP client but sends data as a client.
    # XXX - add support for Connector and Grid
    if (nexus.count('Replication')) | (nexus.count('DataMover')):
        # if this is the replication source(dsp client) then
        # use show-peer-stats
        if (nexus.count('nexus-c')):
            stat_name = 'show-peer-stats'
        else:
            stat_name = 'show-stats'
    else:
        if (nexus.count('Export')):
            stat_name = 'show-peer-stats'
        else:
            stat_name = 'show-stats'

    tag_uuid = 'S:' + nexus.split('-')[-2]

    while True:
        stri = subprocess.Popen([jmxtool, 'dsp', stat_name, nexus],
                                stdout=subprocess.PIPE,
                                text=True).communicate()[0].splitlines()
        for line in stri:
            cols = line.strip().rstrip().split(':')
            dict[cols[0]] = cols[1::]

        if len(prev_dict) == 0:
            prev_dict = dict.copy()
            time.sleep(interval)
            continue

        cmds = int(dict['server.sum.totalCompleted'][0]) - int(
            prev_dict['server.sum.totalCompleted'][0])

        if cmds > active_cmd_threshold:
            my_time = time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())
            disp_lock.acquire()

            complete_time = int((int(dict['server.sum.completeTime'][0]) - int(
                prev_dict['server.sum.completeTime'][0])) / cmds / NS_TO_US)
            dispatch_time = int((int(dict['server.sum.dispatchTime'][0]) - int(
                prev_dict['server.sum.dispatchTime'][0])) / cmds / NS_TO_US)
            execute_time = int((int(dict['server.sum.executeTime'][0]) - int(
                prev_dict['server.sum.executeTime'][0])) / cmds / NS_TO_US)
            pending_time = int((int(dict['server.sum.pendingTime'][0]) - int(
                prev_dict['server.sum.pendingTime'][0])) / cmds / NS_TO_US)
            process_time = int((int(dict['server.sum.processTime'][0]) - int(
                prev_dict['server.sum.processTime'][0])) / cmds / NS_TO_US)
            service_time = int((int(dict['server.sum.serviceTime'][0]) - int(
                prev_dict['server.sum.serviceTime'][0])) / cmds / NS_TO_US)
            dsp_avg_queue = int((int(dict['server.sum.totalActive'][0]) - int(
                prev_dict['server.sum.totalActive'][0])) / cmds)
            iops = int(cmds / interval)

            if aggr:
                print(
                    '{:<25} {:<15} {:>60} {:>10} {:>10} {:>15} {:>15} '
                    '{:>15}'.format(
                        my_time, tag_uuid, '  |  ', dsp_avg_queue, iops,
                        execute_time, pending_time, service_time))
            else:
                if nexus.count('Export'):
                    print('{0:>65} :: {1}'
                          .format(my_time,
                                  'DSP Server(target host side)'))
                else:
                    print('{0:>65} :: {1}'.format(my_time,
                                                  'DSP Server'))

                print('{0:>65} : {1} us'.format('Average complete time',
                                                complete_time))
                print('{0:>65} : {1} us'.format('Average dispatch time',
                                                dispatch_time))
                print('{0:>65} : {1} us'.format('Average execute time',
                                                execute_time))
                print('{0:>65} : {1} us'.format('Average pending time',
                                                pending_time))
                print('{0:>65} : {1} us'.format('Average process time',
                                                process_time))
                print('{0:>65} : {1} us'.format('Average service time',
                                                service_time))
                print(
                    '{0:>65} : {1}'.format('Average DSP queue',
                                           dsp_avg_queue))
                print('{0:>65} : {1}'.format('IOPS', iops))
                print('\n')
            disp_lock.release()

        prev_dict = dict.copy()
        time.sleep(interval)

    return


#
# dsp_client() - dump dsp server side statistics for given nexus
#
def dsp_client(nexus, aggr=False):  # noqa: C901
    global NS_TO_US  # noqa: F824
    global aggr_data  # noqa: F824
    dict = {}
    prev_dict = {}

    # determine which side of the connection is the DSP client
    # replication - Replication Source DE (show-stats)
    # snapsync    - Source Host (show-peer-stats)
    # export(V2P) - Target Host (show-peer-stats)
    # since script could be run on replication source or target check nexus
    # for client or server
    if (nexus.count('Replication')) | (nexus.count('DataMover')):
        # if this is the replication target(dsp server) then
        # use show-peer-stats
        if (nexus.count('nexus-s')):
            stat_name = 'show-peer-stats'
        else:
            stat_name = 'show-stats'
    else:
        if (nexus.count('Export')):
            stat_name = 'show-stats'
        else:
            stat_name = 'show-peer-stats'

    tag_uuid = 'C:' + nexus.split('-')[-2]

    while True:
        stri = subprocess.Popen([jmxtool, 'dsp', stat_name, nexus],
                                stdout=subprocess.PIPE,
                                text=True).communicate()[0].splitlines()
        for line in stri:
            cols = line.strip().rstrip().split(':')
            dict[cols[0]] = cols[1::]

        if len(prev_dict) == 0:
            prev_dict = dict.copy()
            time.sleep(interval)
            continue

        cmds = int(dict['client.sum.totalCompleted'][0]) - int(
            prev_dict['client.sum.totalCompleted'][0])

        if cmds > active_cmd_threshold:
            my_time = time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())
            disp_lock.acquire()

            complete_time = int((int(dict['client.sum.completeTime'][0]) - int(
                prev_dict['client.sum.completeTime'][0])) / cmds / NS_TO_US)
            dispatch_time = int((int(dict['client.sum.dispatchTime'][0]) - int(
                prev_dict['client.sum.dispatchTime'][0])) / cmds / NS_TO_US)
            execute_time = int((int(dict['client.sum.executeTime'][0]) - int(
                prev_dict['client.sum.executeTime'][0])) / cmds / NS_TO_US)
            network_time = int((int(dict['client.sum.networkTime'][0]) - int(
                prev_dict['client.sum.networkTime'][0])) / cmds / NS_TO_US)
            pending_time = int((int(dict['client.sum.pendingTime'][0]) - int(
                prev_dict['client.sum.pendingTime'][0])) / cmds / NS_TO_US)
            dsp_avg_queue = int((int(dict['client.sum.totalActive'][0]) - int(
                prev_dict['client.sum.totalActive'][0])) / cmds)
            total_bytes = (int(dict['client.sum.totalBytes'][0]) - int(
                prev_dict['client.sum.totalBytes'][0]))
            total_cbytes = (
                int(dict['client.sum.totalCompressedBytes'][0]) -  # noqa: W504
                int(prev_dict['client.sum.totalCompressedBytes'][0])
            )
            payload_size = int((total_bytes / cmds) / 1024)
            throughput = int((total_bytes / interval) / 1024)
            cthroughput = int((total_cbytes / interval) / 1024)
            iops = int(cmds / interval)

            if aggr:
                print(
                    '{:<25}{:<15}{:<10}{:<10}{:<15}{:<10}{:<10}{:<5}'.format(
                        my_time, tag_uuid, dsp_avg_queue, iops, network_time,
                        '  ' + str(throughput), str(cthroughput), '  |  '))
            else:
                if (nexus.count('Export')):
                    print('{0} :: {1}'.format(my_time, 'DSP Client(DE Side)'))
                else:
                    print('{0} :: {1}'.format(my_time, 'DSP Client'))
                print('{0:>25} : {1} us'.format('Average complete time',
                                                complete_time))
                print('{0:>25} : {1} us'.format('Average dispatch time',
                                                dispatch_time))
                print('{0:>25} : {1} us'.format('Average execute time',
                                                execute_time))
                print('{0:>25} : {1} us'.format('Average network time',
                                                network_time))
                print('{0:>25} : {1} us'.format('Average pending time',
                                                pending_time))
                print('{0:>25} : {1} KB'.format('Average payload size',
                                                payload_size))
                print(
                    '{0:>25} : {1}'.format('Average DSP queue', dsp_avg_queue))
                print('{0:>25} : {1}'.format('IOPS', iops))
                print('{0:>25} : {1} KB/s'.format('Throughput', throughput))
                print('{0:>25} : {1} KB/s'.format('Compressed Throughput',
                                                  cthroughput))
                print('\n')
            disp_lock.release()
            aggr_lock.acquire()
            aggr_data['raw_tput'] += throughput
            aggr_data['compress_tput'] += cthroughput
            aggr_data['count'] += 1
            aggr_lock.release()
        else:
            # print idle nexus for the client nexus only to prevent
            # messages - if the client didn't complete any commands then
            # the server shouldn't have completed any either.
            print(nexus,
                  ' : Idle Nexus : Active Command Threshold is ',
                  str(active_cmd_threshold),
                  ' and only ',
                  str(cmds),
                  ' command(s) completed in the last interval.')

        prev_dict = dict.copy()
        time.sleep(interval)

    return


def print_aggr_header():
    print('{:^95} {:^100}'.format('Client', 'Server'))
    print('{:>95}{:>5}'.format('| Throughput KB/sec|', '  |  '))
    print(
        '{:<25}{:<15}{:<10}{:<10}{:<15}{:<10}{:<10}{:>5}'
        '{:>10}{:>10}{:>15}{:>15}{:>15}'.format(
            'Date/Time', 'TAG', 'Queue', 'IOPS', 'Network (us)',
            '| Raw', 'Compress |', '  |  ', 'Queue', 'IOPS', 'Execute (us)',
            'Pending (us)', 'Service (us)'))


def start_single(nexus, aggr):
    # Create dameon threads to pull client and server side DSP stats.
    # Use daemon threads so that sys.exit() upon interrupt doesn't try to
    # join on the threads and hang.
    ct = threading.Thread(target=dsp_client, args=(nexus, aggr,))
    time.sleep(1)
    st = threading.Thread(target=dsp_server, args=(nexus, aggr,))
    ct.daemon = True
    st.daemon = True

    # Start both threads

    ct.start()
    st.start()
    return


def start_aggr(nexus_list):
    for nexus in nexus_list:
        start_single(nexus, True)
        time.sleep(5)

    if (len(nexus_list) > 1):
        at = threading.Thread(target=aggr_thread, args=(None,))
        at.daemon = True
        at.start()

    return


parser = argparse.ArgumentParser()
parser.add_argument('--aggr', action='store_true',
                    help='aggregate display')
parser.add_argument('--interval', type=int, default=30,
                    help='interval in seconds between updates (default: 30)')
args = parser.parse_args()

interval = args.interval

# Validate commandline provided nexus, or prompt user from existing nexus
nexus = getnexus()

if (nexus is None):
    print("No Nexus Found.")
    sys.exit(0)

# Single Nexus
#   print nexus status
#   if aggregate option then print aggregate output one line per iteration
#   else print the nexus detailed output (old dsp.py behavior)
# MultiNexus
#   Always display in aggregate form
if (len(nexus) == 1):
    printnexus(nexus[0])
    if args.aggr:
        print_aggr_header()
    start_single(nexus[0], args.aggr)
else:
    print("MultiNexus:")
    for n in nexus:
        print("\t" + n)
    print_aggr_header()
    start_aggr(nexus)

while True:
    time.sleep(60)

sys.exit(0)
