/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <uapi/linux/bpf.h>


// Definitions for this script
#define	READ_STR "read "
#define	WRITE_STR "write "
#define	OP_NAME_LEN 7
#define	NAME_LENGTH (OP_NAME_LEN + 1)
#define	AXIS_LENGTH (DISK_NAME_LEN + 1)

// Structure to hold thread local data
typedef struct {
	u64 ts;
	unsigned int size;
	unsigned int cmd_flags;
	u32 err;
	char device[DISK_NAME_LEN];
} io_data_t;

BPF_HASH(io_base_data, u64, io_data_t);

// @@ kprobe|blk_mq_start_request|disk_io_start
int
disk_io_start(struct pt_regs *ctx, struct request *reqp)
{
	io_data_t data = {};
	struct gendisk *diskp = reqp->rq_disk;
	data.ts = bpf_ktime_get_ns();
	data.cmd_flags = reqp->cmd_flags;
	data.size = reqp->__data_len;
	bpf_probe_read_str(&data.device, DISK_NAME_LEN, diskp->disk_name);
	io_base_data.update((u64 *) &reqp, &data);
	return (0);
}

// @@ kprobe|blk_account_io_done|disk_io_done
int
disk_io_done(struct pt_regs *ctx, struct request *reqp)
{
	u64 ts = bpf_ktime_get_ns();
	io_data_t *data = io_base_data.lookup((u64 *) &reqp);
	struct bio *bp = reqp->bio;

	if (data == 0) {
		return (0);   // missed issue
	}

	u64 delta = ts - data->ts;
	char name[NAME_LENGTH] = "";
	char axis[AXIS_LENGTH] = "";

	data->err = (bp->bi_status == BLK_STS_OK) ? 0 : 1;

	if ((data->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE) {
		__builtin_memcpy(&name, WRITE_STR, OP_NAME_LEN);
	} else {
		__builtin_memcpy(&name, READ_STR, OP_NAME_LEN);
	}

#ifdef OPTARG
	if ((sizeof (OPTARG) == 4) && (OPTARG[0] == 'l') &&
	    (OPTARG[1] == 'u') && (OPTARG[2] == 'n')) {
		__builtin_memcpy(&axis, data->device, AXIS_LENGTH);
	}
#endif

	// Perform aggregations
	AGGREGATE_DATA(name, axis, delta, data->size);
	io_base_data.delete((u64 *) &reqp);
	return (0);
}
