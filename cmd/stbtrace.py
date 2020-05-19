#!/usr/bin/env python3
#
# Copyright 2019 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run bcc string template tracing scripts.
#

import argparse
import json
import os
import sys
base_dir = os.path.dirname(__file__) + "/../"
if not os.path.exists(base_dir + "lib/iterative_template.py"):
    base_dir = "/usr/share/performance-diagnostics/"
sys.path.append(base_dir + 'lib/')
from iterative_template import IterativeTemplate    # noqa: E402

parser = argparse.ArgumentParser(
        description='stbtrace (String Template Bcc trace) '
                    'runs bcc kernel tracing scripts used by delphix '
                    'analytics to monitor various subsystems.  String '
                    'templates provide a mechanism to customize the '
                    'tracers by turning collection axis on and off.  '
                    'Two input files are required for each tracer.  '
                    'The first is a tracing script written using string '
                    'template syntax defined at org.stringtemplate.v4.  '
                    'Secondly, a json data files to provide the values '
                    'for the template fields that are used in the script. '
                    'The scripts collects statistics over time intervals '
                    'and other callection axis.  By default all '
                    'statistics specified in the data file '
                    'are collected along all axis specified.  '
                    'The data file also includes a collection period '
                    'in nanoseconds that specifies the frequency that '
                    'the statistics are reported.',
        usage='%(prog)s tracer [options] ')
parser.add_argument("tracer", type=str,
                    help="io|iscsi|nfs|vfs|zio|zpl")
parser.add_argument('-f', '--fields', action='store_true', dest='fields',
                    help='Show available statistics and axis for '
                         'the specified tracing script')
parser.add_argument('-a', '--axes', action='store', dest='AXIS',
                    help='A comma separated list specifying collection '
                         'axis or "None"')
parser.add_argument('-s', '--stats', action='store', dest='STATS',
                    help='A comma separated list of statistics to '
                         'collect')
parser.add_argument('-c', '--coll', type=int, action='store',
                    dest='collection_sec',
                    help='The collection interval in seconds')
parser.add_argument('-b', '--bcc', action='store_true', dest='bcc',
                    help='Emit the bcc script without executing it')
parser.add_argument('-p', '--path', action='store', dest='PATH',
                    help='Provide path to input files')
args = parser.parse_args()


# read json data file to discover available collection fields

if args.PATH:
    filename = args.PATH + '/' + args.tracer + '.json'
else:
    filename = base_dir + '/bpf/stbtrace/' + args.tracer + '.json'
try:
    with open(filename, 'r') as json_file:
        data = json.load(json_file)
except IOError as e:
    print("Error reading " + filename + ": " + e.strerror)
    exit()
except ValueError:
    print("Error reading " + filename + ": invalid format")
    exit()

if args.fields:
    print(args.tracer + " fields")
    print("axes:")
    for key in data['keys'].keys():
        print("   " + key)
    print("statistics:")
    for map in data['maps'].keys():
        print("   " + map)
    for hist in data['hists'].keys():
        print("   " + hist)
    exit()

#
# Read the template script and initialize IterativeTemplate
#
if args.PATH:
    filename = args.PATH + '/' + args.tracer + '.st'
else:
    filename = base_dir + '/bpf/stbtrace/' + args.tracer + '.st'

try:
    with open(filename, 'r') as f:
        file_content = f.read()
except IOError as e:
    print("Error reading " + filename + ": " + e.strerror)
    exit()

template = IterativeTemplate(file_content)

for axis in data['keys']:
    template.addFields('keys', data['keys'][axis])

for map in data['maps']:
    template.addFields('maps', data['maps'][map])

for hist in data['hists']:
    template.addFields('hists', data['hists'][hist])

if args.AXIS:
    template.selectFields('keys', args.AXIS.split(","))

if args.STATS:
    template.selectFields('maps', args.STATS.split(","))
    template.selectFields('hists', args.STATS.split(","))

if args.collection_sec:
    template.addSingleton('collection_period_in_ns',
                          args.collection_sec * 1000000000)
else:
    for node in data:
        if node != 'keys' and \
           node != 'maps' and \
           node != 'hists' and \
           node != 'title':
            template.addSingleton(node, data[node])

# Perform template substitutions and execute or output the resulting script
script = template.render()
if args.bcc:
    print(script, end='')
    exit(0)
else:
    try:
        exec(script)
    except KeyboardInterrupt:
        exit(0)
    except Exception as e:
        print(e)
        exit(1)
