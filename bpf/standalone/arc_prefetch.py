#!/usr/bin/env python3
#
# Copyright (c) 2020, 2016 by Delphix. All rights reserved.
#

#
# This script provides read latency data for prefetch I/O.
#
# usage: arc-prefetch.d <zpool-name>
#

from bcc import BPF
from time import sleep
from time import strftime
import argparse
import os
import sys

#
# Find BCCHelper. If we are being run from the repo, we should be able to find
# it in the repo's lib/ directory. If we can't find that, look for BCCHelper
# in its install location.
#
base_dir = os.path.dirname(__file__) + "/../../"
if not os.path.exists(base_dir + "lib/bcchelper.py"):
    base_dir = "/usr/share/performance-diagnostics/"
sys.path.append(base_dir + 'lib/')
# flake8 wants these at the top of the file, but path update must come first
from bcchelper import BCCHelper            # noqa: E402
from bcchelper import BCCMapIndex          # noqa: E402
from bcchelper import BCCPerCPUIntArray    # noqa: E402
from bcchelper import BCCPoolCompare       # noqa: E402


bpf_text = '#include "' + base_dir + 'lib/bcc_helper.h' + '"\n'
bpf_text += """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>

#include <sys/uio.h>
#include <sys/condvar.h>
#include <sys/xvattr.h>
#include <sys/zfs_rlock.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_objset.h>
#include <sys/spa_impl.h>
#include <sys/arc_impl.h>
"""
parser = argparse.ArgumentParser(
        description='Collect arc_prefetch statistics.',
        usage='estat arc-prefetch [options]')
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
#define ARC_FLAG_PREFETCH    (1 << 2)        /* I/O is a prefetch */

typedef struct {
    u64 zfs_read_ts;
    u64 arc_read_ts;
    zio_t *zio;
}arc_prefetch_info_t;

typedef struct {
    u64 t;
    u32 index;
    u64 cpuid;
} lat_key;

HIST_KEY(hist_lat_key, lat_key);

BPF_HASH(arc_prefetch_info, u32, arc_prefetch_info_t);
BPF_HASH(zio_read_exit_time, zio_t *, u64);

BPF_HASH(read_latency, hist_lat_key, u64);
BPF_HASH(read_average, lat_key, average_t);
BPF_PERCPU_ARRAY(arc_count, u32, NCOUNT_INDEX);

int zfs_read_entry(struct pt_regs *ctx, struct znode *zn)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    arc_prefetch_info_t info = {ts};

    // filter by pool
    zfsvfs_t *zfsvfs = zn->z_inode.i_sb->s_fs_info;
    objset_t *z_os = zfsvfs->z_os;
    spa_t *spa = z_os->os_spa;
    if (POOL_COMPARE(spa))
        arc_prefetch_info.update(&tid, &info);

    return 0;
}

int zfs_read_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);

    if (info == NULL)
        return 0;

    if (info != NULL)
        arc_prefetch_info.delete(&tid);
    return 0;
}


int arc_hit_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);
    if (info == NULL || info->zfs_read_ts == 0)
        return 0;

    arc_count.increment(ARC_HIT_COUNT);
    return 0;
}

int arc_miss_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);
    if (info == NULL || info->zfs_read_ts == 0)
        return 0;

    arc_count.increment(ARC_MISS_COUNT);
    return 0;
}

int arc_read_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);
    if (info == NULL || info->zfs_read_ts == 0)
        return 0;

    info->arc_read_ts = bpf_ktime_get_ns();
    return 0;
}

int arc_read_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);
    if (info == NULL || info->arc_read_ts == 0)
        return 0;

    u64 elapsed = (bpf_ktime_get_ns() - info->arc_read_ts) / 1000;
    lat_key lkey = {1, ARC_ISSUE_LATENCY, 0};
    lkey.cpuid = bpf_get_smp_processor_id();
    u32 slot = bpf_log2l(elapsed);
    HIST_KEY_INITIALIZE(hist_lat_key, hkey, lkey, slot);
    read_latency.increment(hkey);

    average_t *average = read_average.lookup(&lkey);
    if (average == NULL) {
         average_t initial_average = {1, elapsed};
         read_average.update(&lkey, &initial_average);
         return 0;
    }
    average->count += 1;
    average->sum += elapsed;
    return 0;
}

int zio_read_entry(struct pt_regs *ctx, zio_t *zio)
{
    u32 tid = bpf_get_current_pid_tgid();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);
    if (info == NULL || info->arc_read_ts == 0)
        return 0;

    info->zio = zio;
    return 0;
}

int zio_read_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 zio_exit_ts = bpf_ktime_get_ns();
    arc_prefetch_info_t *info = arc_prefetch_info.lookup(&tid);
    if (info == NULL || info->zio == NULL)
        return 0;

    zio_read_exit_time.update(&info->zio, &zio_exit_ts);
    return 0;
}

int arc_read_done_entry(struct pt_regs *ctx, zio_t *zio)
{
    arc_buf_hdr_t *hdr = (arc_buf_hdr_t *) zio->io_private;
    u64 zero = 0;

    u64 *zio_exit_ts = zio_read_exit_time.lookup(&zio);
    if (zio_exit_ts == NULL || *zio_exit_ts == 0) {
            return 0;
    }

    u64 zio_ts = *zio_exit_ts;
    u64 elapsed = (bpf_ktime_get_ns() - zio_ts) / 1000;

    hist_lat_key hkey = { };
    lat_key *lkey = HIST_KEY_GET_AGGKEY(&hkey);
    u32 count_index;
    if (hdr->b_flags & ARC_FLAG_PREFETCH) {
        count_index = ARC_PREFETCH_ZIO_COUNT;
        lkey->index = ARC_PREFETCH_ZIO_LATENCY;
    } else {   // normal zio
        count_index = ARC_NORMAL_ZIO_COUNT;
        lkey->index = ARC_NORMAL_ZIO_LATENCY;
    }
    lkey->t = 1;
    lkey->cpuid = bpf_get_smp_processor_id();

    HIST_KEY_SET_SLOT(&hkey, bpf_log2(elapsed));
    arc_count.increment(count_index);
    read_latency.increment(hkey);
    zio_read_exit_time.update(&zio, &zero);
    average_t *average = read_average.lookup(lkey);
    if (average == NULL) {
         average_t initial_average = {1, elapsed};
         read_average.update(lkey, &initial_average);
         return 0;
    }
    average->count += 1;
    average->sum += elapsed;

    return 0;
 }

"""


class ArcCountIndex(BCCMapIndex):
    ARC_HIT_COUNT = (0, 'ARC_HIT_COUNT', 'prefetch hit count')
    ARC_MISS_COUNT = (1, 'ARC_MISS_COUNT', 'prefetch miss count')
    ARC_NORMAL_ZIO_COUNT = (2, 'ARC_NORMAL_ZIO_COUNT', 'normal read count')
    ARC_PREFETCH_ZIO_COUNT = (3, 'ARC_PREFETCH_ZIO_COUNT',
                              'prefetch read count')


class ArcLatencyIndex(BCCMapIndex):
    ARC_ISSUE_LATENCY = (0, 'ARC_ISSUE_LATENCY', 'arc read latency')
    ARC_NORMAL_ZIO_AVERAGE = (1, 'ARC_NORMAL_ZIO_LATENCY',
                              'normal read latency')
    ARC_PREFETCH_ZIO_AVERAGE = (2, 'ARC_PREFETCH_ZIO_LATENCY',
                                'prefetch read latency')


KVER = os.popen('uname -r').read().rstrip()

flags = ["-include",
         "/usr/src/zfs-" + KVER + "/zfs_config.h",
         "-include",
         "/usr/src/zfs-" + KVER + "/include/spl/sys/types.h",
         "-I/usr/src/zfs-" + KVER + "/include/",
         "-I/usr/src/zfs-" + KVER + "/include/spl/",
         "-I/usr/src/zfs-" + KVER + "/include/linux",
         "-DNCOUNT_INDEX=" + str(len(ArcCountIndex)),
         "-DNAVERAGE_INDEX=" + str(len(ArcLatencyIndex))] \
         + ArcCountIndex.getCDefinitions() \
         + ArcLatencyIndex.getCDefinitions()

b = BPF(text=bpf_text, cflags=flags)

b.attach_kprobe(event="zfs_read", fn_name="zfs_read_entry")
b.attach_kretprobe(event="zfs_read", fn_name="zfs_read_return")
b.attach_kprobe(event="trace_zfs_arc__hit", fn_name="arc_hit_entry")
b.attach_kprobe(event="trace_zfs_arc__miss", fn_name="arc_miss_entry")
b.attach_kprobe(event="arc_read", fn_name="arc_read_entry")
b.attach_kretprobe(event="arc_read", fn_name="arc_read_return")
b.attach_kprobe(event="zio_read", fn_name="zio_read_entry")
b.attach_kretprobe(event="zio_read", fn_name="zio_read_return")
b.attach_kprobe(event="arc_read_done", fn_name="arc_read_done_entry")

read_latency_helper = BCCHelper(b, BCCHelper.ESTAT_PRINT_MODE)
read_latency_helper.add_aggregation("read_latency",
                                    BCCHelper.LOG_HISTOGRAM_AGGREGATION,
                                    "microseconds")
read_latency_helper.add_aggregation("read_average",
                                    BCCHelper.AVERAGE_AGGREGATION,
                                    "avg latency(us)")
read_latency_helper.add_key_type("index", BCCHelper.MAP_INDEX_TYPE,
                                 ArcLatencyIndex)
call_count_helper = BCCPerCPUIntArray(b, "arc_count", ArcCountIndex)


while True:
    try:
        sleep(5)
    except KeyboardInterrupt:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        call_count_helper.printall()
        read_latency_helper.printall()
        break
    try:
        print("%-16s\n" % strftime("%D - %H:%M:%S %Z"))
        call_count_helper.printall()
        read_latency_helper.printall()
    except Exception as e:
        print(str(e))
        break
