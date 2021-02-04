/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include "target/iscsi/iscsi_target_core.h"


// Definitions for this script
#define	READ_STR "read"
#define	WRITE_STR "write"

#define	OP_NAME_LEN 6
#define	NAME_LENGTH (OP_NAME_LEN + 1)

typedef struct {
	u64 ts;
	u64 size;
} iscsi_data_t;


BPF_HASH(iscsi_base_data, u64, iscsi_data_t);

// @@ kprobe|iscsit_process_scsi_cmd|iscsi_target_start
int
iscsi_target_start(struct pt_regs *ctx, struct iscsi_conn *conn,
    struct iscsi_cmd *cmd, struct iscsi_scsi_req *hdr)
{
	iscsi_data_t data = {};
	data.ts = bpf_ktime_get_ns();
	data.size = hdr->data_length;
	iscsi_base_data.update((u64 *) &cmd, &data);

	return (0);
}

static int
aggregate_data(iscsi_data_t *data, u64 ts, char *opstr)
{
	u64 delta;
	char name[NAME_LENGTH] = "";
	char axis = 0;

	delta = ts - data->ts;
	__builtin_memcpy(&name, opstr, OP_NAME_LEN);

	// Perform aggregations
	AGGREGATE_DATA(name, &axis, delta, data->size);
	return (0);
}

// @@ kprobe|iscsit_build_rsp_pdu|iscsi_target_end
// @@ kprobe|iscsit_build_datain_pdu|iscsi_target_end
int
iscsi_target_end(struct pt_regs *ctx, struct iscsi_cmd *cmd)
{
	u64 ts = bpf_ktime_get_ns();
	iscsi_data_t *data = iscsi_base_data.lookup((u64 *) &cmd);
	u64 delta;

	if (data == 0) {
		return (0);   // missed issue
	}

	if (cmd->data_direction == DMA_FROM_DEVICE) {
		aggregate_data(data, ts, READ_STR);
	} else if (cmd->data_direction & DMA_TO_DEVICE) {
		aggregate_data(data, ts, WRITE_STR);
	}
	iscsi_base_data.delete((u64 *) &cmd);

	return (0);
}
