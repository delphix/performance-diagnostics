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
#include <sys/zio.h>
#include <sys/fs/zfs.h>

// Structure to hold thread local data
#define OP_NAME_LEN 6
typedef struct {
    u64 ts;
} zio_data_t;

// Key structure for scalar aggegations maps
typedef struct {
    u64  t;
    $keys:{key| $key.declaration$
    }$
    u64  cpuid;
} zio_key_t;

HIST_KEY(zio_hist_key_t, zio_key_t);

BPF_HASH(zio_base_data, zio_t *, zio_data_t);
$maps:{map|
BPF_HASH($map.name$, zio_key_t, $map.type$);
}$
$hists:{hist|
BPF_HASH($hist.name$, zio_hist_key_t, u64);
}$

// Probe functions to initialize thread local data
int vdev_queue_issue_return(struct pt_regs *ctx)
{
    zio_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    zio_t *zio = (zio_t *)PT_REGS_RC(ctx);
    zio_base_data.update(&zio, &data);

    return 0;
}

/*
 * BCC won't allow an argument with an opname array indexed
 * by a variable, like:
 * __builtin_memcpy(&key.op, opname[zio->io_type], OP_NAME_LEN);
 * BCC does allow this if statement.  It's in a function so that
 * it can be used easily by the template code with no
 * references to the key.op if the op axis is not active.
 */
static void update_op(char **opstr, int type)
{
    if (type == ZIO_TYPE_READ)
        __builtin_memcpy(opstr, "read", OP_NAME_LEN);
    else if (type == ZIO_TYPE_WRITE)
        __builtin_memcpy(opstr, "write", OP_NAME_LEN);
    else if (type == ZIO_TYPE_FREE)
        __builtin_memcpy(opstr, "free", OP_NAME_LEN);
    else if (type == ZIO_TYPE_CLAIM)
        __builtin_memcpy(opstr, "claim", OP_NAME_LEN);
    else if (type == ZIO_TYPE_IOCTL)
        __builtin_memcpy(opstr, "ioctl", OP_NAME_LEN);
    else
        __builtin_memcpy(opstr, "null", OP_NAME_LEN);
}

int vdev_queue_done(struct pt_regs *ctx, zio_t *zio)
{
    u64 ts = bpf_ktime_get_ns();
    zio_data_t *data = zio_base_data.lookup(&zio);
    zio_key_t key = {};
    u64 delta;
    u64 iosize = zio->io_size;

    if (data == 0) {
        return 0;   // missed issue
    }

    delta = ts - data->ts;
    key.t = ts / $collection_period_in_ns$;
    key.cpuid = bpf_get_smp_processor_id();
    $keys:{key| $key.collect$
    }$

    $maps:{map|
        $map.aggregation$;
    }$

    zio_hist_key_t hist_key = {};
    hist_key.agg_key = key;

    $hists:{hist|
        hist_key.slot = $hist.slot$;
        $hist.name$.increment(hist_key);
    }$

    zio_base_data.delete(&zio);
    return 0;
}


"""

KVER = os.popen('uname -r').read().rstrip()
b = BPF(text=bpf_text, cflags=["-include",
                               "/usr/src/zfs-" + KVER + "/zfs_config.h",
                               "-I/usr/src/zfs-" + KVER + "/include/",
                               "-I/usr/src/zfs-" + KVER + "/include/spl/",
                               "-I/usr/src/zfs-" + KVER + "/include/linux"])

b.attach_kretprobe(event="vdev_queue_io_to_issue", fn_name="vdev_queue_issue_return")
b.attach_kprobe(event="vdev_queue_io_done", fn_name="vdev_queue_done")

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
