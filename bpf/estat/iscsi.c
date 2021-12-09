/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* 
 * This tracer provides latency and througphput data for the iscsi target 
 * read and writes. The latency is measured from entering 
 * iscsit_process_scsi_cmd() to exiting iscsit_target_response(). The
 * thread that enters iscsi_process_scsi_cmd() will put an entry on the
 * request task queue. This entry will be removed from the queue and
 * processed by another thread which calls iscsi_target_response.
 * The tracing is performed by three probe functions.
 * 1. iscsi_target_start - This function saves a timestamp of the entry
 *    into iscsit_process_scsi_cmd() hashed by a pointer to the iscssi_cmd.
 * 2. iscsi_target_response - This function serves the purpose of moving
 *    the timestamp saved by iscsi_target_start to a thread id based hash.
 *    Also the size and direction are stored in the hash since kretprobes
 *    do not have access to parameters.
 * 3. iscsi_target_end - This function retrieves the hashed base data by
 *    thread id and performs the data aggregation.
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
	u32 direction;
} iscsi_data_t;


BPF_HASH(iscsi_start_ts, u64, u64);
BPF_HASH(iscsi_base_data, u32, iscsi_data_t);

// @@ kprobe|iscsit_process_scsi_cmd|iscsi_target_start
int
iscsi_target_start(struct pt_regs *ctx, struct iscsi_conn *conn,
    struct iscsi_cmd *cmd, struct iscsi_scsi_req *hdr)
{
	u64 ts = bpf_ktime_get_ns();
	iscsi_start_ts.update((u64 *) &cmd, &ts);

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



// @@ kprobe|iscsit_response_queue|iscsi_target_response
int
iscsi_target_response(struct pt_regs *ctx, struct iscsi_conn *conn, struct iscsi_cmd *cmd, int state)
{
	u32 tid = bpf_get_current_pid_tgid();
	iscsi_data_t data = {};

	u64 *tsp = iscsi_start_ts.lookup((u64 *) &cmd);
	if (tsp == 0) {
		return (0);   // missed issue
	}

	data.ts = *tsp;
	data.size = cmd->se_cmd.data_length;
	data.direction = cmd->data_direction;

	iscsi_base_data.update(&tid, &data);
	iscsi_start_ts.delete((u64 *) &cmd);

	return (0);
}

// @@ kretprobe|iscsit_response_queue|iscsi_target_end
int
iscsi_target_end(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u32 tid = bpf_get_current_pid_tgid();
	iscsi_data_t *data = iscsi_base_data.lookup(&tid);

	if (data == 0) {
		return (0);   // missed issue
	}

	if (data->direction == DMA_FROM_DEVICE) {
		aggregate_data(data, ts, READ_STR);
	} else if (data->direction == DMA_TO_DEVICE) {
		aggregate_data(data, ts, WRITE_STR);
	}
	iscsi_base_data.delete(&tid);

	return (0);
}
