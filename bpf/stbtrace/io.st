#
# Copyright (c) 2019, 2020 by Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from bcc import BPF
from time import sleep
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
from bcchelper import BCCHelper   # noqa: E402


# BPF disk io program
bpf_text = '#include "' + base_dir + 'lib/bcc_helper.h' + '"\n'
bpf_text += """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <uapi/linux/bpf.h>

// Definitions for this script
#define READ_STR "read"
#define WRITE_STR "write"
#define OP_NAME_LEN 6

// Structure to hold thread local data
typedef struct {
    u64 ts;
    unsigned int size;
    unsigned int cmd_flags;
    u32 err;
    char device[DISK_NAME_LEN];
} io_data_t;

// Key structure for scalar aggegations maps
typedef struct {
    u64  t;
    $keys:{key| $key.declaration$
    }$
    u64  cpuid;
} io_key_t;

HIST_KEY(io_hist_key_t, io_key_t);

BPF_HASH(io_base_data, u64, io_data_t);
$maps:{map|
BPF_HASH($map.name$, io_key_t, $map.type$);
}$
$hists:{hist|
BPF_HASH($hist.name$, io_hist_key_t, u64);
}$

int disk_io_start(struct pt_regs *ctx, struct request *reqp)
{
    io_data_t data = {};
    struct gendisk *diskp = reqp->rq_disk;
    data.ts = bpf_ktime_get_ns();
    data.cmd_flags = reqp->cmd_flags;
    data.size = reqp->__data_len;
    __builtin_memcpy(&data.device, diskp->disk_name, DISK_NAME_LEN);
    io_base_data.update((u64 *) &reqp, &data);
    return 0;
}

static int aggregate_data(io_data_t *data, u64 ts, char *opstr)
{
    u64 delta;
    io_key_t key = {};

    delta = ts - data->ts;
    key.t = ts / $collection_period_in_ns$;
    key.cpuid = bpf_get_smp_processor_id();
    $keys:{key| $key.collect$
    }$

    $maps:{map|
        $map.aggregation$;
    }$

    io_hist_key_t hist_key = {};
    hist_key.agg_key = key;

    $hists:{hist|
        hist_key.slot = $hist.slot$;
        $hist.name$.increment(hist_key);
    }$

    return 0;
}

int disk_io_done(struct pt_regs *ctx, struct request *reqp)
{
    u64 ts = bpf_ktime_get_ns();
    io_data_t *data = io_base_data.lookup((u64 *) &reqp);
    struct bio *bp = reqp->bio;

    if (data == 0) {
        return 0;   // missed issue
    }

    data->err = (bp->bi_status == BLK_STS_OK) ? 0 : 1;

    // Perform aggregations
    if ((data->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE) {
        aggregate_data(data, ts, WRITE_STR);
    } else {
        aggregate_data(data, ts, READ_STR);
    }

    io_base_data.delete((u64 *) &reqp);
    return 0;
}
"""  # noqa: W293
b = BPF(text=bpf_text)

if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="disk_io_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="disk_io_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="disk_io_done")


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
