#!/usr/bin/env python3
#
# Copyright 2019 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

#
# ZFS write latency can be broken up into two categories:
# - Writing to memory (asynchronous write)
# - Committing to disk (synchronous write)
# It's worth noting that the synchronous write code path must execute both of
# the above components so careful examination will be necessary to determine
# which component is contributing to the slowness.
#
# This script looks closer into the write code path. It displays the latency
# of async/synchronous writes. For synchronous writes it also includes the
# time to commit ZIL log blocks. Comparing the zil_commit time and the
# synchronous write path will help determine if further investigation is
# needed into the asynchronous code path (i.e. the TXG transaction engine) or
# the zil_commit code path.
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
from bcchelper import BCCHelper       # noqa: E402
from bcchelper import BCCMapIndex     # noqa: E402
from bcchelper import BCCPoolCompare  # noqa: E402

# define BPF program
bpf_text = '#include "' + base_dir + 'lib/bcc_helper.h' + '"\n'
bpf_text += """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include <sys/file.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_vfsops.h>
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

# Add pool POOL_COMPARE macro to the bpf_text C code
if (args.pool):
    pool = args.pool
else:
    pool = "domain0"
pool_compare = BCCPoolCompare(pool)
if not pool_compare.get_pool_pointer():
    print("Warning: No pool filtering, unable to find zfs pool " + pool)
bpf_text += pool_compare.get_pool_compare_code()

bpf_text += """
typedef struct {
    u64 write_ts;
    u64 commit_ts;
    u32 sync;
} zfs_write_info_t;

BPF_HASH(zfs_info_map, u32, zfs_write_info_t);

typedef struct {
    u64 t;
    u32 sync;
    u32 cpuid;
} zfs_key_t;
HIST_KEY(zfs_hist_key_t, zfs_key_t);
BPF_HASH(zfs_write_latency, zfs_hist_key_t, u64);

typedef struct {
    u64 t;
    u32 cpuid;
} zil_key_t;
HIST_KEY(zil_hist_key_t, zil_key_t);
BPF_HASH(zil_commit_latency, zil_hist_key_t, u64);

int zfs_write_entry(struct pt_regs *ctx, struct inode *ip,
uio_t *uio, int ioflag)
{
    u32 tid = bpf_get_current_pid_tgid();
    zfs_write_info_t info = {};

    info.write_ts = bpf_ktime_get_ns();
    zfsvfs_t *zfsvfs = ip->i_sb->s_fs_info;
    objset_t *z_os = zfsvfs->z_os;
    spa_t *spa = z_os->os_spa;
    if (!POOL_COMPARE(spa))
                return 0;

    info.sync = ioflag & (O_SYNC | O_DSYNC) ||
            zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS;
    zfs_info_map.update(&tid, &info);
    return 0;
}

int zfs_write_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    zfs_key_t key = {};

    zfs_write_info_t *info = zfs_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }
    key.t = 1;
    key.cpuid = bpf_get_smp_processor_id();
    key.sync = info->sync;
    u32 slot = bpf_log2l(ts - info->write_ts);
    HIST_KEY_INITIALIZE(zfs_hist_key_t, hkey, key, slot);
    zfs_write_latency.increment(hkey);

    zfs_info_map.delete(&tid);

    return 0;
}

int zil_commit_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    zfs_write_info_t *info = zfs_info_map.lookup(&tid);
    if (info == NULL)
        return 0;
    info->commit_ts = bpf_ktime_get_ns();
    return 0;
}

int zil_commit_return(struct pt_regs *cts)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    zil_key_t key = {};

    zfs_write_info_t *info = zfs_info_map.lookup(&tid);
    if (info == NULL) {
        return 0;
    }
    key.t = 1;
    key.cpuid = bpf_get_smp_processor_id();
    u32 slot = bpf_log2l(ts - info->write_ts);
    HIST_KEY_INITIALIZE(zil_hist_key_t, hkey, key, slot);
    zil_commit_latency.increment(hkey);

    return 0;
}

"""


class SynchronizationIndex(BCCMapIndex):
    ARC_ISSUE_LATENCY = (0, 'ASYNC', 'asynchronous')
    ARC_NORMAL_ZIO_AVERAGE = (1, 'SYNC', 'synchronus')


# load BPF program
KVER = os.popen('uname -r').read().rstrip()
b = BPF(text=bpf_text,
        cflags=["-include",
                "/usr/src/zfs-" + KVER + "/zfs_config.h",
                "-I/usr/src/zfs-" + KVER + "/include/",
                "-I/usr/src/zfs-" + KVER + "/include/spl",
                "-I/usr/src/zfs-" + KVER + "/include/",
                "-I/usr/src/zfs-" + KVER + "/include/linux",
                "-DCC_USING_FENTRY"])

b.attach_kprobe(event="zfs_write", fn_name="zfs_write_entry")
b.attach_kretprobe(event="zfs_write", fn_name="zfs_write_return")
b.attach_kprobe(event="zil_commit", fn_name="zil_commit_entry")
b.attach_kretprobe(event="zil_commit", fn_name="zil_commit_return")

zfs_helper = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
zfs_helper.add_key_type("sync", BCCHelper.MAP_INDEX_TYPE,
                        SynchronizationIndex)
zfs_helper.add_aggregation("zfs_write_latency",
                           BCCHelper.LOG_HISTOGRAM_AGGREGATION)
zil_helper = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
zil_helper.add_aggregation("zil_commit_latency",
                           BCCHelper.LOG_HISTOGRAM_AGGREGATION)

if (not args.collection_sec):
    print(" Tracing enabled... Hit Ctrl-C to end.")

# Collect data for a collection interval if specified
if (args.collection_sec):
    sleep(args.collection_sec)
    try:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        zfs_helper.printall()
        zil_helper.printall()
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
        zfs_helper.printall()
        zil_helper.printall()
        break
    try:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        zfs_helper.printall()
        zil_helper.printall()
    except Exception as e:
        print(str(e))
        break
