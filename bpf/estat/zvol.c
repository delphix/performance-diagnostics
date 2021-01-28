/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>

#include <sys/zil_impl.h>
#include <sys/zfs_rlock.h>
#include <sys/spa_impl.h>
#include <sys/dataset_kstats.h>
#include <sys/zvol_impl.h>


#define	ZVOL_WCE 0x8
#define	ZVOL_READ 1
#define	ZVOL_WRITE 2
#define	NAME_LENGTH 6
#define	AXIS_LENGTH 6
#define	READ_LENGTH 5
#define	WRITE_LENGTH 6
#define	SYNC_LENGTH 5
#define	ASYNC_LENGTH 6

#ifndef OPTARG
#define	POOL "domain0"
#else
#define	POOL (OPTARG)
#endif


// Structure to hold thread local data
typedef struct {
	u64 ts;
	u64 bytes;
	u32 op;
	zvol_state_t *zv;
} zvol_data_t;

typedef struct zv_request {
	zvol_state_t	*zv;
	struct bio	*bio;
} zv_request_t;


BPF_HASH(zvol_base_data, u32, zvol_data_t);

static inline bool equal_to_pool(char *str)
{
	char comparand[sizeof (POOL)];
	bpf_probe_read(&comparand, sizeof (comparand), str);
	char compare[] = POOL;
	for (int i = 0; i < sizeof (comparand); ++i)
		if (compare[i] != comparand[i])
			return (false);
	return (true);
}

static void
zvol_entry(zv_request_t *zvr, int op)
{
	zvol_data_t data = {};
	data.ts = bpf_ktime_get_ns();
	data.op = op;
	u32 pid = bpf_get_current_pid_tgid();
	struct bio *bio = zvr->bio;
	data.bytes = bio->bi_iter.bi_size;
	data.zv = zvr->zv;

	zvol_base_data.update(&pid, &data);
}


// @@ kprobe|zvol_read|zvol_read_entry
int
zvol_read_entry(struct pt_regs *ctx, zv_request_t *zvr)
{
	zvol_entry(zvr, ZVOL_READ);
	return (0);
}

// @@ kprobe|zvol_write|zvol_write_entry
int
zvol_write_entry(struct pt_regs *ctx, zv_request_t *zvr)
{
	zvol_entry(zvr, ZVOL_WRITE);
	return (0);
}


// @@ kretprobe|zvol_read|zvol_return
// @@ kretprobe|zvol_write|zvol_return
int
zvol_return(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	zvol_data_t *data = zvol_base_data.lookup(&pid);
	if (data == 0) {
		return (0);   // missed issue
	}
	u64 delta = ts - data->ts;

	zvol_state_t *zv = data->zv;

	if (! equal_to_pool(zv->zv_objset->os_spa->spa_name))
		return (0);

	int sync = zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS ? 1 :
	    (zv->zv_flags & ZVOL_WCE) ? 0 : 1;

	char name[NAME_LENGTH];
	char axis[AXIS_LENGTH];
	if (data->op == ZVOL_READ) {
		axis[0] = '\0';
		__builtin_memcpy(&name, "read", READ_LENGTH);
	} else if (sync) {
		__builtin_memcpy(&name, "write", WRITE_LENGTH);
		__builtin_memcpy(&axis, "sync", SYNC_LENGTH);
	} else {
		__builtin_memcpy(&name, "write", WRITE_LENGTH);
		__builtin_memcpy(&axis, "async", ASYNC_LENGTH);
	}
	AGGREGATE_DATA(name, axis, delta, data->bytes);
	zvol_base_data.delete(&pid);

	return (0);
}
