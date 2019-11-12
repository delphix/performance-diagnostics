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
#include <linux/sunrpc/svc.h>
#include "/opt/delphix/server/etc/bcc_helper.h"


// nfsd4 definitions from fs/nfsd/xdr4.h
#define u32 unsigned int
#define u64 unsigned long long
#define bool int

typedef struct {
    u32             cl_boot;
    u32             cl_id;
} clientid_t;

typedef struct {
    clientid_t      so_clid;
    u32             so_id;
} stateid_opaque_t;

typedef struct {
    u32                     si_generation;
    stateid_opaque_t        si_opaque;
} stateid_t;

typedef struct {
    stateid_t       rd_stateid;     /* request */
    u64		    rd_offset;      /* request */
    u32             rd_length;      /* request */
    int             rd_vlen;
    struct file     *rd_filp;
    bool            rd_tmp_file;
    void            *rd_rqstp;      /* response */
    void            *rd_fhp;        /* response */
} nfsd4_read;

#define NFS4_VERIFIER_SIZE      8
typedef struct { char data[NFS4_VERIFIER_SIZE]; } nfs4_verifier;

typedef struct {
    stateid_t       wr_stateid;         /* request */
    u64             wr_offset;          /* request */
    u32             wr_stable_how;      /* request */
    u32             wr_buflen;          /* request */
    struct kvec     wr_head;
    struct page **  wr_pagelist;        /* request */
    u32             wr_bytes_written;   /* response */
    u32             wr_how_written;     /* response */
    nfs4_verifier   wr_verifier;        /* response */
} nfsd4_write;

// Definitions for this script
#define READ_STR "read"
#define WRITE_STR "write"
#define NFSV3_STR "v3"
#define NFSV4_STR "v4"
#define OP_NAME_LEN 6
#define VER_NAME_LEN 3
// Max length for null terminated string with ipv4 literal address
#define MAX_IP_STRING 16
// Client ip is sometimes proceeded by "*," or ","
#define CLIENT_PREFIX_LEN 2
#define CLIENT_LEN (MAX_IP_STRING + CLIENT_PREFIX_LEN)
#define SYNC_WRITE  1
#define ASYNC_WRITE 0
#define CACHED_READ 1
#define NONCACHED_READ 0
#define AXIS_NOT_APPLICABLE -1

// Structure to hold thread local data
typedef struct {
    u64 ts;
    u64 size;
    void *write_arg;
    int sync;   // 1=sync write, 0=async write, -1=read
    int cached; // 1=cached read, 0=non-cached read, -1=write
    char client[CLIENT_LEN];
} nfs_data_t;

// Key structure for scalar aggegations maps
typedef struct {
    u64  t;
    $keys:{key| $key.declaration$
    }$
    u32  cpuid;
} nfs_key_t;

HIST_KEY(nfs_hist_key_t, nfs_key_t);

BPF_HASH(nfs_base_data, u32, nfs_data_t);
$maps:{map|
BPF_HASH($map.name$, nfs_key_t, $map.type$);
}$
$hists:{hist|
BPF_HASH($hist.name$, nfs_hist_key_t, u64);
}$

// Probe functions to initialize thread local data
int nfsd3_read_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *fhp,
    u64 offset, void *vec, int vlen, u32 *count)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.write_arg = count;
    data.sync = AXIS_NOT_APPLICABLE;
    data.cached = CACHED_READ; // Assume cache hit, misses detected
    bpf_probe_read_str(&data.client, CLIENT_LEN, rqstp->rq_client->name);
    nfs_base_data.update(&pid, &data);
    return 0;
}

int nfsd3_write_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *fhp,
    u64 offset, void *vec, int vlen, u32 *count)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.write_arg = count;
    data.sync = ASYNC_WRITE; // Assume async write, sync writes detected
    data.cached = AXIS_NOT_APPLICABLE;
    bpf_probe_read_str(&data.client, CLIENT_LEN, rqstp->rq_client->name);
    nfs_base_data.update(&pid, &data);
    return 0;
}

int nfsd4_read_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *cstate,
    nfsd4_read *nfs_read)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.size = nfs_read->rd_length;
    data.write_arg = 0;
    data.sync = AXIS_NOT_APPLICABLE;
    data.cached = CACHED_READ; // Assume cache hit, misses detected
    bpf_probe_read_str(&data.client, CLIENT_LEN, rqstp->rq_client->name);
    nfs_base_data.update(&pid, &data);
    return 0;
}

int nfsd4_write_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *cstate,
    nfsd4_write *nfs_write)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.size = 0;
    data.write_arg = nfs_write;
    data.sync = ASYNC_WRITE; // Assume async write, sync writes detected
    data.cached = AXIS_NOT_APPLICABLE;
    bpf_probe_read_str(&data.client, CLIENT_LEN, rqstp->rq_client->name);
    nfs_base_data.update(&pid, &data);

    return 0;
}

int nfs_cache_miss(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t *data = nfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    data->cached = NONCACHED_READ;

    return 0;
}

int zil_commit_start(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t *data = nfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    data->sync = SYNC_WRITE;
    return 0;
}


// Perform aggregations
static int aggregate_data(nfs_data_t *data, u64 ts, char *opstr, char *verstr)
{
    u64 delta;
    delta = ts - data->ts;

    nfs_key_t key = {};
    $keys:{key| $key.collect$
    }$
    key.t = ts / $collection_period_in_ns$;
    key.cpuid = bpf_get_smp_processor_id();

    $maps:{map|
        $map.aggregation$;
    }$

    nfs_hist_key_t hist_key = {};
    hist_key.agg_key = key;

    $hists:{hist|
        hist_key.slot = $hist.slot$;
        $hist.name$.increment(hist_key);
    }$

    return 0;
}

static int nfsd3_aggregate_data(u64 ts, char *opstr)
{
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t *data = nfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }
    bpf_probe_read(&data->size, sizeof(u32), data->write_arg);

    aggregate_data(data, ts, opstr, NFSV3_STR);
    nfs_base_data.delete(&pid);

    return 0;
}

// Probe functions to aggregate data
int nfsd3_read_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    return nfsd3_aggregate_data(ts, READ_STR);
}

int nfsd3_write_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    return nfsd3_aggregate_data(ts, WRITE_STR);
}

int nfsd4_read_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t *data = nfs_base_data.lookup(&pid);

    if (data == 0) {
        return 0;   // missed issue
    }

    aggregate_data(data, ts, READ_STR, NFSV4_STR);
    nfs_base_data.delete(&pid);

    return 0;
}

int nfsd4_write_done(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    nfs_data_t *data = nfs_base_data.lookup(&pid);
    nfsd4_write nfs_write;

    if (data == 0) {
        return 0;   // missed issue
    }

    bpf_probe_read(&nfs_write, sizeof(nfs_write), data->write_arg);
    data->size = nfs_write.wr_bytes_written;

    aggregate_data(data, ts, WRITE_STR, NFSV4_STR);
    nfs_base_data.delete(&pid);

    return 0;
}
"""
b = BPF(text=bpf_text)

b.attach_kprobe(event="nfsd_read", fn_name="nfsd3_read_start")
b.attach_kprobe(event="nfsd_write", fn_name="nfsd3_write_start")
b.attach_kretprobe(event="nfsd_read", fn_name="nfsd3_read_done")
b.attach_kretprobe(event="nfsd_write", fn_name="nfsd3_write_done")
b.attach_kprobe(event="nfsd4_read", fn_name="nfsd4_read_start")
b.attach_kprobe(event="nfsd4_write", fn_name="nfsd4_write_start")
b.attach_kretprobe(event="nfsd4_read_release", fn_name="nfsd4_read_done")
b.attach_kretprobe(event="nfsd4_write", fn_name="nfsd4_write_done")
b.attach_kprobe(event="trace_zfs_arc__miss", fn_name="nfs_cache_miss")
b.attach_kprobe(event="trace_zfs_blocked__read", fn_name="nfs_cache_miss")
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
