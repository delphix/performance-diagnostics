#!/usr/bin/env python3
#
# Copyright 2019 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

#
# Tool for helping with performance observability of various subsystems
# which could have notable processing involved and subsystems involved
# in the core data I/O path with focus on latency, specifically:
# - latency histograms by I/O type
# - latency histograms by I/O size and type
# - I/O size histograms
# - average latency, stddev latency, IOPs, throughput by I/O type
# I/O type
# - This is split into "name" (like "read"/"write") and additional
#   qualifier called "axis" (like "async" / "sync") as needed by
#   the performance data collector.
#

from bcc import BPF
import getopt
from glob import glob
import os
import sys
from time import sleep, strftime

#
# We need to find BCCHelper.  If being run from the repo, we should find
# it in the repo's lib/ directory.  If we can't find that directory, look
# for BCCHelper in its install location.
#
base_dir = os.path.dirname(__file__) + "/../"
if not os.path.exists(base_dir + "lib/bcchelper.py"):
    base_dir = "/usr/share/performance-diagnostics/"
sys.path.append(base_dir + 'lib/')
from bcchelper import BCCHelper   # noqa: E402


def die(*args, **kwargs):
    print(sys.argv[0] + ": ", file=sys.stderr, end="")
    print(*args, file=sys.stderr, **kwargs)
    exit(1)


programs_dir = base_dir + 'bpf/estat/'
programs = [os.path.splitext(os.path.basename(s))[0]
            for s in glob(programs_dir + '*.c')]
programs.sort()

standalones_dir = base_dir + 'bpf/standalone/'
standalones = [os.path.splitext(os.path.basename(s))[0]
               for s in glob(standalones_dir + '*.py')]
standalones.sort()

#
# estat uses the subcommand style to specify which program to run. Standard
# estat are added to the help message automatically, but standalone programs
# must be added manually, since they determin which options they accept.
#
help_msg = "USAGE: {} -h\n".format(sys.argv[0])
help_msg += "       {} [prog] [options]\n".format(sys.argv[0])
help_msg += """
  Tool for running eBPF programs for monitoring performance of various I/O
  related subsystems, focusing on I/O latency. Output can be displayed with
  histograms of I/O broken down by size and type, depending on the provided
  arguments.

OPTIONS:

     -h    show this help message and exit

  The subcommands listed in the following section share common options.
  Each executes the specified tracing program for <duration> seconds,
  displaying various histograms detailing the I/O latency as seen by the
  particular subsystem.
"""
for program in programs:
    help_msg += "\n  estat {:<13} [options] <duration>".format(program)

help_msg += """

      -m        monitor mode; emit data periodically
      -M        monitor mode; emit accumulated data periodically
      -a ARG    argument to the BCC script
      -l/-L     enable/disable latency histograms (default: on)
      -z/-Z     enable/disable size histograms (default: off)
      -q/-Q     enable/disable latency histograms by size (default: off)
      -y/-Y     enable/disable the summary output (default: on)
      -t/-T     enable/disable emitting the summary total (default: on)
      -d LEVEL  set BCC debug level
      -e        emit the resulting eBPF script without executing it

  The subcommands listed in the following section are stand alone tracers.
  Each has it's own options as detailed below.

  estat arc_prefetch [options]
      Collect arc_prefetch statistics for 5 second intervals.
      -h          show txg help message and exit
      -p POOL     set the pool to monitor (default: domain0)

  estat txg [options]
      Collect spa_sync statistics for each txg.
      -h          show txg help message and exit
      -c INTERVAL set the collection interval in seconds
      -p POOL     set the pool to monitor (default: domain0)

  estat zil [POOL]
      Provides a breakdown of time spent doing ZIL-related activities, in
      particular the time spent allocating a block and time spent waiting for
      the write I/O to complete. If POOL is not specified, defaults to tracing
      the pool 'domain0'.

"""


def usage(msg):
    print("{}: {}\n".format(sys.argv[0], msg), file=sys.stderr)
    print(help_msg, file=sys.stderr)
    exit(1)


if len(sys.argv) < 2:
    die("Too few arguments")

if sys.argv[1] == '-h':
    print(help_msg, file=sys.stderr)
    exit(0)

all_progs = programs + standalones
program = sys.argv[1]
if program not in all_progs:
    msg = "Illegal program '{}'. Program must be one of {}".format(
            program, ", ".join(all_progs))
    die(msg)

#
# Execing the standalone program is an easy way to run it, but it does have
# disadvantages: the program must do its own arg parsing, but it doesn't have
# access to the help message, which is defined here. Perhaps they should
# be tied together more closely.
#
if program in standalones:
    os.execl(standalones_dir + program + '.py', program, *sys.argv[2:])

monitor = False
accum = False
script_arg = None
debug_level = 0
dump_bpf = False


class Args:
    pass


args = Args()
setattr(args, "lat_hist", False)
setattr(args, "size_hist", False)
setattr(args, "latsize_hist", False)
setattr(args, "summary", True)
setattr(args, "total", True)

#
# We use getopt rather than argparse because it is very difficult to get
# argparse to generate a good help message when using subparsers to handle
# subcommands. In particular, we want to show all of the subcommands options
# in the help message, and make it clear which the subcommands accept the same
# arguments.
#
try:
    opts, rem_args = getopt.getopt(sys.argv[2:], "hmMa:lLzZqQyYnNtTd:e")
except getopt.GetoptError as err:
    die(err)

for opt, arg in opts:
    if opt == "-h":
        print(help_msg, file=sys.stderr)
        exit(0)
    elif opt == "-m":
        monitor = True
    elif opt == "-M":
        monitor = True
        accum = True
    elif opt == "-a":
        script_arg = arg
    elif opt == "-d":
        try:
            debug_level = int(arg)
        except ValueError as e:
            die(e)
    elif opt == "-e":
        dump_bpf = True
    else:
        switches = {'-l': "lat_hist",
                    '-z': "size_hist",
                    '-q': "latsize_hist",
                    '-y': "summary",
                    '-t': "total"}
        if opt in switches:
            setattr(args, switches[opt], True)
        elif opt.lower() in switches:
            setattr(args, switches[opt.lower()], False)
        else:
            assert False, "unhandled option: " + opt

if len(rem_args) == 0:
    die("Missing duration argument")

if len(rem_args) > 1:
    die("Too many arguments")

try:
    duration = float(rem_args[0])
except ValueError as e:
    die(e)

if not (args.lat_hist or args.size_hist or args.latsize_hist):
    args.lat_hist = True

# Now that we are done parsing arguments, construct the text of the BPF program
try:
    with open(base_dir + 'bpf/estat/' + program + '.c', 'r') as prog_file:
        input_text = prog_file.read()
        if "AGGREGATE_DATA" not in input_text:
            die(program + " is not a valid estat script")
except IOError as e:
    die(e)

# Add generic estat code, based on the options passed in
bpf_text = '#include "' + base_dir + 'lib/bcc_helper.h"'

if args.lat_hist or args.size_hist or args.latsize_hist or args.summary:
    bpf_text += """
#define KEY_NAME_LEN 16
#define KEY_AXIS_LEN 16"""

if args.lat_hist or args.size_hist or args.summary:
    bpf_text += """
typedef struct {
    u64  t;
    char name[KEY_NAME_LEN];
    char axis[KEY_AXIS_LEN];
    u32  cpuid;
} datumv1_key;
HIST_KEY(datumv1_hist_key, datumv1_key);
BPF_HASH(ops, datumv1_key, u64);
BPF_HASH(lata, datumv1_key, u64);
BPF_HASH(lats, datumv1_key, u64);
BPF_HASH(data, datumv1_key, u64);
BPF_HASH(latq, datumv1_hist_key, u64);
BPF_HASH(dataq, datumv1_hist_key, u64);
BPF_HASH(opst, datumv1_key, u64);
BPF_HASH(datat, datumv1_key, u64);"""

if args.latsize_hist:
    bpf_text += """
#define SQSTR_LEN 7
typedef struct {
    u64  t;
    char size[SQSTR_LEN];
    char name[KEY_NAME_LEN];
    char axis[KEY_AXIS_LEN];
    u32  cpuid;
} datumv1_qkey;
HIST_KEY(datumv1_hist_qkey, datumv1_qkey);
BPF_HASH(latsq, datumv1_hist_qkey, u64);"""

if args.lat_hist or args.size_hist or args.summary:
    bpf_text += """
static void aggregate1(char *n, char *a, u64 d, u64 s)
{
    int micro_d = ((d) + 500) / 1000;
    datumv1_key key = {};
    datumv1_hist_key hist_key = {};

    key.t = 1;
    key.cpuid = bpf_get_smp_processor_id();
    bpf_probe_read_str(&key.name, KEY_NAME_LEN, n);
    bpf_probe_read_str(&key.axis, KEY_AXIS_LEN, a);
    hist_key.agg_key = key;"""

    if args.summary:
        bpf_text += """
    ops.increment(key);
    lata.increment(key, micro_d);
    lats.increment(key, micro_d * micro_d);
    data.increment(key, s/1024);"""

    if args.lat_hist:
        bpf_text += """
    hist_key.slot = log_lin_hist_slot(d);
    latq.increment(hist_key);"""

    if args.size_hist:
        bpf_text += """
    hist_key.slot = bpf_log2l(s);
    dataq.increment(hist_key);"""

    bpf_text += """
}"""

if args.latsize_hist:
    bpf_text += """
static void aggregate2(char *n, char *a, u64 d, u64 s)
{
    datumv1_qkey qkey = {};
    datumv1_hist_qkey hist_qkey = {};
    qkey.t = 1;
    qkey.cpuid = bpf_get_smp_processor_id();
    bpf_probe_read_str(&qkey.name, KEY_NAME_LEN, n);
    bpf_probe_read_str(&qkey.axis, KEY_AXIS_LEN, a);

    if (s <= 512)
        __builtin_memcpy(qkey.size, "512", SQSTR_LEN);
    else if(s <= 1024)
        __builtin_memcpy(qkey.size, "1KB", SQSTR_LEN);
    else if(s <= 2 * 1024)
        __builtin_memcpy(qkey.size, "2KB", SQSTR_LEN);
    else if(s <= 4 * 1024)
        __builtin_memcpy(qkey.size, "4KB", SQSTR_LEN);
    else if(s <= 8 * 1024)
        __builtin_memcpy(qkey.size, "8KB", SQSTR_LEN);
    else if(s <= 16 * 1024)
        __builtin_memcpy(qkey.size, "16KB", SQSTR_LEN);
    else if(s <= 32 * 1024)
        __builtin_memcpy(qkey.size, "32KB", SQSTR_LEN);
    else if(s <= 64 * 1024)
        __builtin_memcpy(qkey.size, "64KB", SQSTR_LEN);
    else if(s <= 128 * 1024)
        __builtin_memcpy(qkey.size, "128KB", SQSTR_LEN);
    else if(s <= 256 * 1024)
        __builtin_memcpy(qkey.size, "256KB", SQSTR_LEN);
    else if(s <= 512 * 1024)
        __builtin_memcpy(qkey.size, "512KB", SQSTR_LEN);
    else if(s <= 1024 * 1024)
        __builtin_memcpy(qkey.size, "1MB", SQSTR_LEN);
    else if(s <= 2 * 1024 * 1024)
        __builtin_memcpy(qkey.size, "2MB", SQSTR_LEN);
    else if(s <= 4 * 1024 * 1024)
        __builtin_memcpy(qkey.size, "4MB", SQSTR_LEN);
    else if(s <= 8 * 1024 * 1024)
        __builtin_memcpy(qkey.size, "8MB", SQSTR_LEN);
    else if(s <= 16 * 1024 * 1024)
        __builtin_memcpy(qkey.size, "16MB", SQSTR_LEN);
    else if(s <= 32 * 1024 * 1024)
        __builtin_memcpy(qkey.size, "32MB", SQSTR_LEN);
    else if(s <= 64 * 1024 * 1024)
        __builtin_memcpy(qkey.size, "64MB", SQSTR_LEN);
    else
        __builtin_memcpy(qkey.size, ">64MB", SQSTR_LEN);

    hist_qkey.agg_key = qkey;
    hist_qkey.slot = log_lin_hist_slot(d);
    latsq.increment(hist_qkey);
}"""

if args.summary and args.total:
    bpf_text += """
static void aggregate3(char *n, char *a, u64 d, u64 s)
{
    datumv1_key tkey = {1, "total", 0};
    tkey.cpuid = bpf_get_smp_processor_id();
    opst.increment(tkey);
    datat.increment(tkey, s/1024);
}"""

bpf_text += """
static int AGGREGATE_DATA(char *n, char *a, u64 d, u64 s)
{"""

if args.lat_hist or args.size_hist or args.summary:
    bpf_text += """
    aggregate1(n, a, d, s);"""

if args.latsize_hist:
    bpf_text += """
    aggregate2(n, a, d, s);"""

if args.summary and args.total:
    bpf_text += """
    aggregate3(n, a, d, s);"""

bpf_text += """
    return 0;
}
"""

bpf_text += input_text

if dump_bpf:
    print(bpf_text)
    exit(0)

# Load BPF program
KVER = os.popen('uname -r').read().rstrip()
cflags = ["-include",
          "/usr/src/zfs-" + KVER + "/zfs_config.h",
          "-include",
          "/usr/src/zfs-" + KVER + "/include/spl/sys/types.h",
          "-I/usr/src/zfs-" + KVER + "/include/",
          "-I/usr/src/zfs-" + KVER + "/include/spl"]
if script_arg:
    cflags.append("-DOPTARG=\"" + script_arg + "\"")

b = BPF(text=bpf_text, cflags=cflags, debug=debug_level)

#
# The number of threads that can be executing the body of a function with a
# kretprobe attached at the same time before the kretprobe begins to miss
# events. The default setting can be as low as 10, which is problematic when
# tracing functions which take a long time to return (e.g. zfs_read). Note that
# if the cumulative number of active kretprobes in the system is large, it may
# affect the time it takes to execute a kretprobe (untested), so when we have
# the choice, we should prefer using tracepoints to kretprobes.
#
MAXACTIVE = 512

# Attach probes
probes = set()
for line in input_text.splitlines():
    if "@@" in line:
        probe_spec = line.split()[-1].split("|")
        if len(probe_spec) != 3:
            die("Unexpected probe specification: expected specification in " +
                "form '// @@ kprobe|fn_to_trace|bcc_trace_fn', got '" +
                line + "'")
        probe_type = probe_spec[0]
        if probe_type == "kprobe":
            if BPF.get_kprobe_functions(probe_spec[1].encode('utf-8')):
                b.attach_kprobe(event=probe_spec[1], fn_name=probe_spec[2])
                probes.add("p_" + probe_spec[1] + "_bcc_" + str(os.getpid()))
            else:
                print("WARNING: {}: {} - not found"
                      .format(probe_type, probe_spec[1]))
        elif probe_type == "kretprobe":
            b.attach_kretprobe(event=probe_spec[1], fn_name=probe_spec[2],
                               maxactive=MAXACTIVE)
            probes.add("r_" + probe_spec[1] + "_bcc_" + str(os.getpid()))
        else:
            die("Unknown probe type: expected 'kprobe' or similar, got '" +
                probe_type + "'")

if args.lat_hist or args.size_hist or args.summary:
    helper1 = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
    helper1.add_key_type("name")
    helper1.add_key_type("axis")

    if args.summary:
        helper1.add_aggregation("ops", BCCHelper.COUNT_AGGREGATION, "iops(/s)")
        helper1.add_aggregation("lata", BCCHelper.AVERSUM_AGGREGATION,
                                "avg latency(us)")
        helper1.add_aggregation("lats", BCCHelper.STDDEV_AGGREGATION,
                                "stddev(us)")
        helper1.add_aggregation("data", BCCHelper.SUM_AGGREGATION,
                                "throughput(k/s)")

    if args.lat_hist:
        helper1.add_aggregation("latq", BCCHelper.LL_HISTOGRAM_AGGREGATION,
                                "microseconds")

    if args.size_hist:
        helper1.add_aggregation("dataq", BCCHelper.LOG_HISTOGRAM_AGGREGATION,
                                "bytes")

if args.latsize_hist:
    helper2 = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
    helper2.add_aggregation("latsq", BCCHelper.LL_HISTOGRAM_AGGREGATION,
                            "microseconds")
    helper2.add_key_type("size")
    helper2.add_key_type("name")
    helper2.add_key_type("axis")

if args.summary and args.total:
    helper3 = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
    helper3.add_aggregation("opst", BCCHelper.COUNT_AGGREGATION, "iops(/s)")
    helper3.add_aggregation("datat", BCCHelper.SUM_AGGREGATION,
                            "throughput(k/s)")
    helper3.add_key_type("name")

# Need real time;
print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))  # TODO deduplicate this line
print(" Tracing enabled... Hit Ctrl-C to end.")

# output
if monitor:
    # TODO can we do this without shelling out to 'date'?
    ds__start = int(os.popen("date +%s%N").readlines()[0])
    while (1):
        try:
            sleep(duration)
        except KeyboardInterrupt:
            break
        try:
            ds__end = int(os.popen("date +%s%N").readlines()[0])
            ds__delta = ds__end - ds__start
            if not accum:
                ds__start = ds__end
            helper1.normalize("ops", ds__delta // 1000000000)
            helper1.normalize("data", ds__delta // 1000000000)
            helper3.normalize("opst", ds__delta // 1000000000)
            helper3.normalize("datat", ds__delta // 1000000000)
            clear_data = not accum
            if args.latsize_hist:
                helper2.printall(clear_data)
            if args.lat_hist or args.size_hist or args.summary:
                helper1.printall(clear_data)
            if args.summary and args.total:
                helper3.printall(clear_data)
            print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        except Exception as e:
            die(e)
else:
    ds__start = int(os.popen("date +%s%N").readlines()[0])
    try:
        sleep(duration)
    except KeyboardInterrupt:
        pass
    try:
        ds__delta = int(os.popen("date +%s%N").readlines()[0]) - ds__start
        helper1.normalize("ops", ds__delta // 1000000000)
        helper1.normalize("data", ds__delta // 1000000000)
        helper3.normalize("opst", ds__delta // 1000000000)
        helper3.normalize("datat", ds__delta // 1000000000)
        if args.latsize_hist:
            helper2.printall()
        if args.lat_hist or args.size_hist or args.summary:
            helper1.printall()
        if args.summary and args.total:
            helper3.printall()
    except Exception as e:
        die(e)

#
# Sometimes we see kprobe 'misses' (times when probed function was executed,
# but probe handler didn't run). We don't understand yet what is causing these
# misses, but we can at least report them to warn the user.
#
try:
    with open('/sys/kernel/debug/tracing/kprobe_profile', 'r') as f:
        for line in f.readlines():
            [probe, hits, misses] = line.strip().split()
            if probe in probes and int(misses) > 0:
                print("WARNING: probe {} missed {} of {} events"
                      .format(probe, misses, hits))
except IOError as e:
    die(e)
