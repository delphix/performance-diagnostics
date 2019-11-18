#
# Copyright (c) 2019 by Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from bcc import BPF
from time import sleep
from time import time
import datetime
import ctypes as ct
import os
import sys
#
# Find BCCHelper. If we are being run from the repo, we should be able to find
# it in the repo's lib/ directory. If we can't find that, look for BCCHelper
# in its install location.
#
base_dir = os.path.dirname(__file__) + "/../"
if not os.path.exists(base_dir + "lib/bcchelper.py"):
    base_dir = "/usr/share/performance-diagnostics/"
sys.path.append(base_dir + 'lib/')
from bcchelper import BCCHelper

# BPF txg program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include "/opt/delphix/server/etc/bcc_helper.h"

#include <sys/uio.h>

// Definitions for this script
#define READ_STR "read"
#define WRITE_STR "write"
#define SYNC_WRITE  1
#define ASYNC_WRITE 0
#define CACHED_READ 1
#define NONCACHED_READ 0
#define AXIS_NOT_APPLICABLE -1

// Structure to hold thread local data
#define OP_NAME_LEN 6
typedef struct {
    u64 ts;
    u64 size;
    int sync;
    int cached;
} zpl_data_t;

// Key structure for scalar aggegations maps
typedef struct {
    u64  t;
    $keys:{key| $key.declaration$
    }$
    u32  cpuid;
} zpl_key_t;

HIST_KEY(zpl_hist_key_t, zpl_key_t);

BPF_HASH(zpl_base_data, u32, zpl_data_t);
$maps:{map|
BPF_HASH($map.name$, zpl_key_t, $map.type$);
}$
$hists:{hist|
BPF_HASH($hist.name$, zpl_hist_key_t, u64);
}$

// Probe functions to initialize thread local data
int zfs_read_start(struct pt_regs *ctx, void *inode, uio_t *uio)
{

    u32 pid = bpf_get_current_pid_tgid();
    zpl_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.size = uio->uio_resid;
    data.sync = AXIS_NOT_APPLICABLE; // Only applies to writes
    data.cached = CACHED_READ; // Assume cache hit, misses detected
    zpl_base_data.update(&pid, &data);
    return 0;
}

// Probe functions to initialize thread local data
int zfs_write_start(struct pt_regs *ctx, void *inode, uio_t *uio)
{

    u32 pid = bpf_get_current_pid_tgid();
    zpl_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.size = uio->uio_resid;
    data.sync = ASYNC_WRITE; // Assume async write, sync writes detected
    data.cached = AXIS_NOT_APPLICABLE; // Only applies to reads
    zpl_base_data.update(&pid, &data);
    return 0;
}

int zpl_cache_miss(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    zpl_data_t *data = zpl_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    data->cached = NONCACHED_READ;

    return 0;
}

int zil_commit_start(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    zpl_data_t *data = zpl_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    data->sync = SYNC_WRITE;
    return 0;
}

// Perform aggregations
static int zpl_aggregate_data(u64 ts, char *opstr)
{
    u32 pid = bpf_get_current_pid_tgid();
    zpl_data_t *data = zpl_base_data.lookup(&pid);
    u64 delta;

    if (data == 0) {
        return 0;   // missed issue
    }

    delta = ts - data->ts;

    zpl_key_t key = {};
    $keys:{key| $key.collect$
    }$
    key.t = ts / $collection_period_in_ns$;
    key.cpuid = bpf_get_smp_processor_id();

    $maps:{map|
        $map.aggregation$;
    }$

    zpl_hist_key_t hist_key = {};
    hist_key.agg_key = key;

    $hists:{hist|
        hist_key.slot = $hist.slot$;
        $hist.name$.increment(hist_key);
    }$

    zpl_base_data.delete(&pid);
    return 0;
}

// Probe functions to aggregate data
int zfs_read_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    return zpl_aggregate_data(ts, READ_STR);
}

int zfs_write_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    return zpl_aggregate_data(ts, WRITE_STR);
}

"""
KVER = os.popen('uname -r').read().rstrip()
b = BPF(text=bpf_text,
        cflags=["-I/usr/src/zfs-" + KVER + "/include/spl"])

b.attach_kprobe(event="zfs_read", fn_name="zfs_read_start")
b.attach_kprobe(event="zfs_write", fn_name="zfs_write_start")
b.attach_kretprobe(event="zfs_read", fn_name="zfs_read_done")
b.attach_kretprobe(event="zfs_write", fn_name="zfs_write_done")
b.attach_kprobe(event="trace_zfs_arc__miss", fn_name="zpl_cache_miss")
b.attach_kprobe(event="trace_zfs_blocked__read", fn_name="zpl_cache_miss")
b.attach_kprobe(event="zil_commit", fn_name="zil_commit_start")

helper = BCCHelper(b, BCCHelper.ANALYTICS_PRINT_MODE)
$maps:{map|
helper.add_aggregation("$map.name$", BCCHelper.$map.aggtype$)
}$
$hists:{hist|
helper.add_aggregation("$hist.name$", BCCHelper.$hist.aggtype$)
}$
$keys:{key|
helper.add_key_type("$key.name$", BCCHelper.$key.keytype$)
}$

while (1):
    try:
        sleep(1)
    except KeyboardInterrupt:
        exit()

    helper.printall()
