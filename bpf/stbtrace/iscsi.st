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

# BPF txg program
bpf_text = '#include "' + base_dir + 'lib/bcc_helper.h' + '"\n'
bpf_text += """
#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>

#include "target/iscsi/iscsi_target_core.h"


// Definitions for this script
#define READ_STR "read"
#define WRITE_STR "write"

// Structure to hold thread local data
#define OP_NAME_LEN 6
typedef struct {
    u64 ts;
    u64 flags;
    u64 size;
} iscsi_data_t;

// Key structure for scalar aggegations maps
typedef struct {
    u64  t;
    $keys:{key| $key.declaration$
    }$
    u32  cpuid;
} iscsi_key_t;

HIST_KEY(iscsi_hist_key_t, iscsi_key_t);

BPF_HASH(iscsi_base_data, u64, iscsi_data_t);
$maps:{map|
BPF_HASH($map.name$, iscsi_key_t, $map.type$);
}$
$hists:{hist|
BPF_HASH($hist.name$, iscsi_hist_key_t, u64);
}$

// Probe functions to initialize thread local data
int iscsi_target_start(struct pt_regs *ctx, struct iscsi_conn *conn,
                       struct iscsi_cmd *cmd, struct iscsi_scsi_req *hdr)
{
    iscsi_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.flags = hdr->flags;
    data.size = hdr->data_length;
    iscsi_base_data.update((u64 *) &cmd, &data);

    return 0;
}

static int aggregate_data(iscsi_data_t *data, u64 ts, char *opstr)
{
    u64 delta;
    iscsi_key_t key = {};

    delta = ts - data->ts;
    key.t = ts / $collection_period_in_ns$;
    key.cpuid = bpf_get_smp_processor_id();
    $keys:{key| $key.collect$
    }$

    $maps:{map|
        $map.aggregation$;
    }$

    iscsi_hist_key_t hist_key = {};
    hist_key.agg_key = key;

    $hists:{hist|
        hist_key.slot = $hist.slot$;
        $hist.name$.increment(hist_key);
    }$

    return 0;
}

int iscsi_target_end(struct pt_regs *ctx, struct iscsi_cmd *cmd)
{
    u64 ts = bpf_ktime_get_ns();
    iscsi_data_t *data = iscsi_base_data.lookup((u64 *) &cmd);
    u64 delta;
    iscsi_key_t key = {};
    char *opstr;

    if (data == 0) {
        return 0;   // missed issue
    }

    if (data->flags & ISCSI_FLAG_CMD_READ) {
        aggregate_data(data, ts, READ_STR);
    } else if (data->flags & ISCSI_FLAG_CMD_WRITE) {
        aggregate_data(data, ts, WRITE_STR);
    }
    iscsi_base_data.delete((u64 *) &cmd);

    return 0;
}

"""  # noqa: W293
b = BPF(text=bpf_text)

b.attach_kprobe(event="iscsit_process_scsi_cmd", fn_name="iscsi_target_start")
b.attach_kprobe(event="iscsit_build_rsp_pdu", fn_name="iscsi_target_end")

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
