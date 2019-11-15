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
    int zfs;
} vfs_data_t;

// Key structure for scalar aggegations maps
typedef struct {
    u64  t;
    $keys:{key| $key.declaration$
    }$
    u32  cpuid;
} vfs_key_t;

HIST_KEY(vfs_hist_key_t, vfs_key_t);

BPF_HASH(vfs_base_data, u32, vfs_data_t);
$maps:{map|
BPF_HASH($map.name$, vfs_key_t, $map.type$);
}$
$hists:{hist|
BPF_HASH($hist.name$, vfs_hist_key_t, u64);
}$

// Probe functions to initialize thread local data
int vfs_start(struct pt_regs *ctx, void *file, void *user_buf,
			       u64 count, void *ppos)
{
    u32 pid = bpf_get_current_pid_tgid();
    vfs_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.size = count;
    data.sync = AXIS_NOT_APPLICABLE; // Only applies to writes
    data.cached = AXIS_NOT_APPLICABLE; // Only applies to reads
    data.zfs = 0; // Assume it's not zfs, zfs calls detected
    vfs_base_data.update(&pid, &data);
    return 0;
}

int zfs_read_start(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    vfs_data_t *data = vfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    data->cached = CACHED_READ; // Assume cache hit, misses detected
    data->zfs = 1;              // This is a zfs operation
    return 0;
}

int zfs_write_start(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    vfs_data_t *data = vfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    data->zfs = 1;            // This is a zfs operation
    data->sync = ASYNC_WRITE; // Assume async write, sync writes detected
    return 0;
}

int vfs_cache_miss(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    vfs_data_t *data = vfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }
    data->cached = NONCACHED_READ;

    return 0;
}

int zil_commit_start(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    vfs_data_t *data = vfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }
    data->sync =  SYNC_WRITE;

    return 0;
}

// Perform aggregations
static int vfs_aggregate_data(u64 ts, char *opstr)
{
    u32 pid = bpf_get_current_pid_tgid();
    vfs_data_t *data = vfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    if (data->zfs == 0) {
        vfs_base_data.delete(&pid);
        return 0;   // not a zfs op
    }

    u64 delta;
    delta = ts - data->ts;

    vfs_key_t key = {};
    $keys:{key| $key.collect$
    }$
    key.t = ts / $collection_period_in_ns$;
    key.cpuid = bpf_get_smp_processor_id();

    $maps:{map|
        $map.aggregation$;
    }$

    vfs_hist_key_t hist_key = {};
    hist_key.agg_key = key;

    $hists:{hist|
        hist_key.slot = $hist.slot$;
        $hist.name$.increment(hist_key);
    }$

    vfs_base_data.delete(&pid);
    return 0;
}

// Probe functions to aggregate data
int vfs_read_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    return vfs_aggregate_data(ts, READ_STR);
}

int vfs_write_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    return vfs_aggregate_data(ts, WRITE_STR);
}
"""
b = BPF(text=bpf_text)

b.attach_kprobe(event="vfs_read", fn_name="vfs_start")
b.attach_kprobe(event="vfs_write", fn_name="vfs_start")
b.attach_kretprobe(event="vfs_read", fn_name="vfs_read_done")
b.attach_kretprobe(event="vfs_write", fn_name="vfs_write_done")
b.attach_kprobe(event="zfs_read", fn_name="zfs_read_start")
b.attach_kprobe(event="zfs_write", fn_name="zfs_write_start")
b.attach_kprobe(event="trace_zfs_arc__miss", fn_name="vfs_cache_miss")
b.attach_kprobe(event="trace_zfs_blocked__read", fn_name="vfs_cache_miss")
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
