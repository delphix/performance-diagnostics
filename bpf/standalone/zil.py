#!/usr/bin/env python3
#
# Copyright 2019 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

#
# The ZIL (ZFS Intent Log) is responsible for providing synchronous write
# semantics in ZFS. Once you've determined that the majority of the write
# latency is attributed to the synchronous write code path you will want to
# use this script to investigate further.
#
# The ZIL latency can be broken down into two main components:
# - time to allocate a block
# - time to wait for the block write to complete
# This BCC script can be used to provide a breakdown of time spent doing
# the allocation and time spent waiting for the write I/O to complete.
#
# This script can be invoked using the 'estat' command.
#

from bcc import BPF
from time import sleep, strftime
import argparse
import sys
import os
base_dir = os.path.dirname(__file__) + "/../../"
if not os.path.exists(base_dir + "lib/bcchelper.py"):
    base_dir = "/usr/share/performance-diagnostics/"
sys.path.append(base_dir + 'lib/')
from bcchelper import BCCHelper   # noqa: E402

# define BPF program
bpf_text = '#include "' + base_dir + 'lib/bcc_helper.h' + '"\n'
bpf_text += """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include <sys/xvattr.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_objset.h>
#include <sys/spa_impl.h>
#include <sys/zil_impl.h>
"""

parser = argparse.ArgumentParser(
        description='Collect zil latency statistics.',
        usage='estat zil [options]')
parser.add_argument('-c', '--coll', type=int, action='store',
                    dest='collection_sec',
                    help='The collection interval in seconds')
parser.add_argument('-p', '--pool', type=str, action='store',
                    dest='pool',
                    help='The pool to monitor (default: domain0)')
args = parser.parse_args()

if (args.pool):
    bpf_text += '#define POOL "' + str(args.pool) + '"'
else:
    bpf_text += '#define POOL "domain0"'

bpf_text += """
typedef struct {
    u64 write_ts;
    u64 commit_ts;
    u64 lwb_ts;
    u64 io_ts;
    int sync;
    int alloc_count;
} zil_tid_info_t;

BPF_HASH(zil_info_map, u32, zil_tid_info_t);

#define NAME_LENGTH 20

typedef struct {
    u64 t;
    char name[NAME_LENGTH];
    u32 cpuid;
} zil_key_t;

HIST_KEY(zil_hist_key_t, zil_key_t);

BPF_HASH(average_latency, zil_key_t, average_t);
BPF_HASH(average_allocs, zil_key_t, average_t);
BPF_HASH(zil_latency, zil_hist_key_t, u64);

static inline bool equal_to_pool(char *str)
{
    char comparand[sizeof(POOL)];
    bpf_probe_read(&comparand, sizeof(comparand), str);
    char compare[] = POOL;
    for (int i = 0; i < sizeof(comparand); ++i)
        if (compare[i] != comparand[i])
            return false;
    return true;
}

static int latency_average_and_histogram(char *name, u64 delta)
{
    zil_key_t key = {};
    __builtin_memcpy(&key.name, name, NAME_LENGTH);
    key.t = 1;
    key.cpuid = bpf_get_smp_processor_id();
    zil_hist_key_t hist_key = {};
    hist_key.agg_key = key;
    average_t zero_avg = ZERO_AVERAGE;
    average_t *avg = average_latency.lookup_or_init(&key, &zero_avg);
    avg->count++;
    avg->sum += delta;
    hist_key.slot = bpf_log2l(delta);
    zil_latency.increment(hist_key);

    return 0;
}

int zfs_write_entry(struct pt_regs *ctx, struct znode *zn,
void *uio, int ioflag)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t info = {};

    info.write_ts = bpf_ktime_get_ns();
    zfsvfs_t *zfsvfs = zn->z_inode.i_sb->s_fs_info;
    objset_t *z_os = zfsvfs->z_os;
    spa_t *spa = z_os->os_spa;
    if (!equal_to_pool(spa->spa_name))
                return 0;

    info.alloc_count = 0;
    info.sync = ioflag & (O_SYNC | O_DSYNC) ||
            zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS;
    zil_info_map.update(&tid, &info);
    return 0;
}

int zfs_write_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }

    if (info->sync)
         latency_average_and_histogram("zfs_write sync",
             (bpf_ktime_get_ns() - info->write_ts) / 1000);
    else
         latency_average_and_histogram("zfs_write async",
             (bpf_ktime_get_ns() - info->write_ts) / 1000);

    zil_info_map.delete(&tid);
    return 0;
}


int zil_commit_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL)
        return 0;
    info->commit_ts = bpf_ktime_get_ns();
    return 0;
}

int zil_commit_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }

    latency_average_and_histogram("zil_commit",
             (bpf_ktime_get_ns() - info->commit_ts) / 1000);

    zil_key_t key = {};
    key.t = 1;
    key.cpuid = bpf_get_smp_processor_id();
    __builtin_memcpy(&key.name, "Allocations", NAME_LENGTH);
    average_t zero_avg = ZERO_AVERAGE;
    average_t *avg = average_allocs.lookup_or_init(&key, &zero_avg);
    avg->count++;
    avg->sum += 10; //info->alloc_count;
    return 0;
}

// First major call in zil_commit_writer()
int zil_get_commit_list_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL)
        return 0;
    info->lwb_ts = ts;
    return 0;
}

// last major call in zil_commit_writer
int zil_process_commit_list_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }


    return latency_average_and_histogram("allocation",
             (bpf_ktime_get_ns() - info->lwb_ts) / 1000);
}

int zil_commit_waiter_entry(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }
    info->io_ts = bpf_ktime_get_ns();
    return 0;
}

int zil_commit_waiter_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }

    return latency_average_and_histogram("io wait",
             (bpf_ktime_get_ns() - info->io_ts) / 1000);
}

int zio_alloc_zil_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    zil_tid_info_t *info = zil_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }
    info->alloc_count++;
    return 0;
}

"""

# load BPF program
KVER = os.popen('uname -r').read().rstrip()
b = BPF(text=bpf_text,
        cflags=["-include",
                "/usr/src/zfs-" + KVER + "/zfs_config.h",
                "-include",
                "/usr/src/zfs-" + KVER + "/include/spl/sys/types.h",
                "-I/usr/src/zfs-" + KVER + "/include/",
                "-I/usr/src/zfs-" + KVER + "/include/spl"])

b.attach_kprobe(event="zfs_write", fn_name="zfs_write_entry")
b.attach_kretprobe(event="zfs_write", fn_name="zfs_write_return")
b.attach_kprobe(event="zil_commit", fn_name="zil_commit_entry")
b.attach_kretprobe(event="zil_commit", fn_name="zil_commit_return")
b.attach_kretprobe(event="zil_process_commit_list",
                   fn_name="zil_process_commit_list_return")
b.attach_kprobe(event="zil_get_commit_list",
                fn_name="zil_get_commit_list_entry")
b.attach_kprobe(event="zil_commit_waiter",
                fn_name="zil_commit_waiter_entry")
b.attach_kretprobe(event="zil_commit_waiter",
                   fn_name="zil_commit_waiter_return")
b.attach_kretprobe(event="zio_alloc_zil", fn_name="zio_alloc_zil_return")

latency_helper = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
latency_helper.add_aggregation("average_latency",
                               BCCHelper.AVERAGE_AGGREGATION, "avg")
latency_helper.add_aggregation("zil_latency",
                               BCCHelper.LOG_HISTOGRAM_AGGREGATION, "latency")
latency_helper.add_key_type("name")

alloc_helper = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
alloc_helper.add_aggregation("average_allocs",
                             BCCHelper.AVERAGE_AGGREGATION, "avg")
alloc_helper.add_key_type("name")

if (not args.collection_sec):
    print(" Tracing enabled... Hit Ctrl-C to end.")

# Collect data for a collection interval if specified
if (args.collection_sec):
    sleep(args.collection_sec)
    try:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        latency_helper.printall()
        alloc_helper.printall()
        exit(0)
    except Exception as e:
        print(str(e))
        exit(0)

# Collect data until keyborad interrupt with output for each second
while True:
    try:
        sleep(60)
    except KeyboardInterrupt:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        latency_helper.printall()
        alloc_helper.printall()
        break
    try:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        latency_helper.printall()
        alloc_helper.printall()
    except Exception as e:
        print(str(e))
        break
