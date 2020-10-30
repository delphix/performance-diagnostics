#!/usr/bin/env python3
#
# Copyright 2019 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
#
# This script prints out information about every spa_sync() for the domain0
# zpool. This allows us to find a point in the past where I/O performance
# degraded and some high-level symptoms about why it's slower now than it was,
# which may be enough to correlate the change to a configuration /
# environmental change.
#

from bcc import BPF, PerfType, PerfSWConfig
import argparse
import os
import drgn
from datetime import datetime

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <sys/spa_impl.h>
#include <linux/sched.h>
"""
parser = argparse.ArgumentParser(
        description='Collect spa_sync statistics for each txg.',
        usage='estat txg [options]')
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
    spa_t *spa;
    u64 start;
    u64 stop;
    u64 time_since_last_sync;
    u64 pool_sync_enter;
    u64 elapsed_pass1;
    u64 delay_entry_time;
    u64 txg;
    u64 throttle;
    u64 delay_max;
    u64 delay_sum;
    u64 delay_count;
} spa_sync_info;

typedef struct {
    u64  txg;
    u64  time_since_last_sync;
    u64  sync_time;
    u64  elapsed_pass1;
    u64  dirty_b;
    u64  throttle;
    u64  delay_max;
    u64  delay_sum;
    u64  delay_count;
} spa_sync_data;

typedef struct {
    u64 *dirty_addr;
    u64 dirty_max;
} spa_sync_dirty;

#define SPA_SYNC_DIRTY_INDEX  0;

BPF_HASH(sync_info_map, u32, spa_sync_info);
BPF_ARRAY(sync_dirty_map, spa_sync_dirty, 1);
BPF_PERF_OUTPUT(sync_events);

/*
 * Store the spa_t address if the pool name matches POOL,
 * "domain0" by default. Should only have to do the string
 * comparision once.
 */

static inline void pool_set(spa_sync_info *info, spa_t *spa)
{
    char comparand[sizeof(POOL)];
    bpf_probe_read(&comparand, sizeof(comparand), spa->spa_name);
    char compare[] = POOL;
    for (int i = 0; i < sizeof(comparand); ++i)
       if (compare[i] != comparand[i])
           return;
    info->spa = spa;
}

/*
 * Get the domain0 spa object and store "start" time and
 * "time since last sync".
 */
int spa_sync_entry(struct pt_regs *ctx, spa_t *spa, uint64_t txg)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL) {
       spa_sync_info spa_info = {};
       sync_info_map.insert(&tid, &spa_info);
       info = &spa_info;

       int dirty_index = SPA_SYNC_DIRTY_INDEX;
       spa_sync_dirty *spa_dirty;
       spa_dirty = sync_dirty_map.lookup(&dirty_index);
       if (spa_dirty != NULL) {
           spa_dirty->dirty_addr = &spa->spa_dsl_pool->dp_dirty_total;
           spa_dirty->dirty_max = spa->spa_dsl_pool->dp_dirty_total;
       }
    }

    if (info->spa == 0)
        pool_set(info, spa);

    if (info->spa != spa)
        return 0;

    info->start = bpf_ktime_get_ns();
    info->txg = txg;
    /*
     * We may not have a "stop" time yet, so just print a (kind of bogus)
     * zero value for "time since last sync" if that's the case. This only
     * affects the first txg we see -- after that "stop" will be set by the
     * previous txg.
     */
    info->time_since_last_sync = info->stop != 0 ?
        info->start - info->stop : 0;
    info->pool_sync_enter = 0;
    info->delay_entry_time = 0;
    info->delay_max = 0;
    return 0;
}

/*
 * Collect data required to know the percentage of syncing time spent
 * in pass 1.
 */
int dsl_pool_sync_entry(struct pt_regs *ctx, dsl_pool_t *dp)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL || info->spa != dp->dp_spa ||
        info->spa->spa_sync_pass != 1) {
        return 0;
    }

    info->pool_sync_enter =  bpf_ktime_get_ns();
    return 0;
}

int dsl_pool_sync_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL || info->pool_sync_enter == 0) {
        return 0;
    }

    info->elapsed_pass1 = bpf_ktime_get_ns() - info->pool_sync_enter;
    return 0;
}

/*
 * Collect data to know how much we're being throttled / delayed. If we're
 * throttled on every tx we could hit these probes a lot (burning CPU), so
 * processing in the probe should be kept to a minimum.
 */
int dmu_tx_delay_entry(struct pt_regs *ctx, dmu_tx_t *tx, uint64_t dirty)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL || info->spa != tx->tx_pool->dp_spa) {
        return 0;
    }

    info->delay_entry_time = bpf_ktime_get_ns();
    return 0;
}
int dmu_tx_delay_mintime(struct pt_regs *ctx, dmu_tx_t *tx, uint64_t dirty,
                         uint64_t min_tx_time)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL || info->delay_entry_time == 0) {
        return 0;
    }

    if (min_tx_time > info->throttle) {
        info->throttle = min_tx_time;
    }
    return 0;
}

int dmu_tx_delay_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL || info->delay_entry_time == 0) {
        return 0;
    }

    u64 elapsed = bpf_ktime_get_ns() - info->delay_entry_time;
    if (elapsed > info->delay_max) {
       info->delay_max = elapsed;
    }

    info->delay_count = info->delay_count + 1;
    info->delay_sum = info->delay_sum + elapsed;
    return 0;
}

/*
 * Submit an event containing the collected stats for each
 * completed spa sync and reset counters.
 */
int spa_sync_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    spa_sync_info *info = sync_info_map.lookup(&tid);
    if (info == NULL || info->pool_sync_enter == 0) {
        return 0;
    }
    info->stop =  bpf_ktime_get_ns();


    spa_sync_data data = {};
    data.txg = info->txg;
    data.time_since_last_sync = info->time_since_last_sync;
    data.sync_time = info->stop - info->start;
    data.elapsed_pass1 = info->elapsed_pass1;

    data.throttle = info->throttle;
    data.delay_max = info->delay_max;
    data.delay_sum = info->delay_sum;
    data.delay_count = info->delay_count;

    int dirty_index = SPA_SYNC_DIRTY_INDEX;
    spa_sync_dirty *dirty = sync_dirty_map.lookup(&dirty_index);
    if (dirty == NULL) {
        data.dirty_b = info->spa->spa_dsl_pool->dp_dirty_total;
    } else {
        data.dirty_b = dirty->dirty_max;
        dirty->dirty_max = 0;
    }

    sync_events.perf_submit(ctx, &data, sizeof(data));
    info->throttle = 0;
    info->start = 0;
    info->spa = 0;

    return 0;
}

/*
 * Record how much dirty data we've collected so far. The value doesn't need to
 * be exact, so we just check this periodically.
 */
int get_spa_dirty(struct bpf_perf_event_data *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    int dirty_index = SPA_SYNC_DIRTY_INDEX;
    spa_sync_dirty *dirty = sync_dirty_map.lookup(&dirty_index);
    if (dirty == NULL) {
        return 0;
    }

    if (*dirty->dirty_addr > dirty->dirty_max) {
        dirty->dirty_max = *dirty->dirty_addr;
    }

    return 0;
}
"""


def read_zfs_dirty_max_data():
    """ Use the drgn program object to read the
        zfs_dirty_data_max kernel variable.
    """
    global proj
    variable = prog['zfs_dirty_data_max']
    return int(variable.value_())


def print_event(cpu, data, size):
    """ Print the raw txg data and a legend at the start and
        after every 30 events.
    """
    event_format = ('{:<24} {:>10} {:>5}ms {:>5}ms ({:>2} pass 1)'
                    '{:>4}MB ({:>2}) {:>4}us {:>5}ms {:>4}ms')
    global print_count
    if (print_count == 30):
        print("        date                 txg     time"
              " since last sync")
        print("         |                    |         |"
              "   sync time")
        print("         |                    |         |"
              "        |  (%% pass 1)")
        print("         |                    |         |"
              "        |    |     highest dirty (%%) ")
        print("         |                    |         |"
              "        |    |           |  highest throttle delay")
        print("         |                    |         |"
              "        |    |           |            |      |  avg delay")
        print("         v                    v         v"
              "        v    v           v            v      v       v")
        #
        # Here is an example line:
        #  "Fri Jan 17 21:21:16 2020       1827162     0ms   1342ms (60% p1) \
        #   208MB (10%)    0us    57ms    10ms"
        #
        print_count = 0
    print_count = print_count + 1

    zfs_dirty_max_data = read_zfs_dirty_max_data()
    event = b["sync_events"].event(data)
    date = datetime.now()
    average_delay = 0
    if (event.delay_count > 1):
        average_delay = event.delay_sum / event.delay_count
    print(event_format.format(date.ctime(),
                              event.txg,
                              int(event.time_since_last_sync / 1000 / 1000),
                              int(event.sync_time / 1000 / 1000),
                              int(event.elapsed_pass1 * 100 / event.sync_time),
                              int(event.dirty_b / 1024 / 1024),
                              int(event.dirty_b * 100 / zfs_dirty_max_data),
                              int((event.throttle + 999) / 1000),
                              event.delay_max,
                              average_delay))


# load BPF program
KVER = os.popen('uname -r').read().rstrip()
b = BPF(text=bpf_text,
        cflags=["-include",
                "/usr/src/zfs-" + KVER + "/zfs_config.h",
                "-I/usr/src/zfs-" + KVER + "/include/",
                "-I/usr/src/zfs-" + KVER + "/include/spl",
                "-I/usr/src/zfs-" + KVER + "/include/",
                "-I/usr/src/zfs-" + KVER + "/include/linux"])

b.attach_kprobe(event="spa_sync", fn_name="spa_sync_entry")
b.attach_kretprobe(event="spa_sync", fn_name="spa_sync_return")
b.attach_kprobe(event="dsl_pool_sync", fn_name="dsl_pool_sync_entry")
b.attach_kretprobe(event="dsl_pool_sync", fn_name="dsl_pool_sync_return")
b.attach_kprobe(event="dmu_tx_delay", fn_name="dmu_tx_delay_entry")
b.attach_kprobe(event="trace_zfs_delay__mintime",
                fn_name="dmu_tx_delay_mintime")
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
                    ev_config=PerfSWConfig.CPU_CLOCK,
                    fn_name="get_spa_dirty",
                    sample_freq=10)

print_count = 30

# initialize dgrn program object to read zfs_dirty_data_max
prog = drgn.program_from_kernel()

# loop with callback to print_event
b["sync_events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
