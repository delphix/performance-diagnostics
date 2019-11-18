/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include <linux/sunrpc/svc.h>


// nfsd4 definitions from fs/nfsd/xdr4.h
#define	u32 unsigned int
#define	u64 unsigned long long
#define	bool int

typedef struct {
	u32	cl_boot;
	u32	cl_id;
} clientid_t;

typedef struct {
	clientid_t	so_clid;
	u32		so_id;
} stateid_opaque_t;

typedef struct {
	u32			si_generation;
	stateid_opaque_t	si_opaque;
} stateid_t;

typedef struct {
	stateid_t	rd_stateid;	/* request */
	u64		rd_offset;	/* request */
	u32		rd_length;	/* request */
	int		rd_vlen;
	struct file	*rd_filp;
	bool		rd_tmp_file;

	void		*rd_rqstp;	/* response */
	void		*rd_fhp;	/* response */
} nfsd4_read;

#define	NFS4_VERIFIER_SIZE	8
typedef struct { char data[NFS4_VERIFIER_SIZE]; } nfs4_verifier;

typedef struct {
	stateid_t	wr_stateid;		/* request */
	u64		wr_offset;		/* request */
	u32		wr_stable_how;		/* request */
	u32		wr_buflen;		/* request */
	struct kvec	wr_head;
	struct page	**wr_pagelist;		/* request */
	u32		wr_bytes_written;	/* response */
	u32		wr_how_written;		/* response */
	nfs4_verifier	wr_verifier;		/* response */
} nfsd4_write;

// Definitions for this script
#define	READ_STR "read"
#define	WRITE_STR "write"
#define	NFSV3_STR "v3"
#define	NFSV4_STR "v4"
#define	OP_NAME_LEN 6
#define	VER_NAME_LEN 3
// Max length for null terminated string with ipv4 literal address
#define	MAX_IP_STRING 16
// Client ip is sometimes proceeded by "*," or ","
#define	CLIENT_PREFIX_LEN 2
#define	CLIENT_LEN (MAX_IP_STRING + CLIENT_PREFIX_LEN)
#define	SYNC_WRITE  1
#define	ASYNC_WRITE 0
#define	CACHED_READ 1
#define	NONCACHED_READ 0
#define	AXIS_NOT_APPLICABLE -1

// Structure to hold thread local data
typedef struct {
	u64 ts;
	u64 size;
	void *write_arg;
	int sync;   // 1=sync write, 0=async write, -1=read
	int cached; // 1=cached read, 0=non-cached read, -1=write
	char client[CLIENT_LEN];
} nfs_data_t;

BPF_HASH(nfs_base_data, u32, nfs_data_t);

#define	IO_TYPE_READ   1
#define	IO_TYPE_WRITE  2
// sync/async/uncached/cached
#define	IO_SUBTYPE_LEN  8
#define	AXIS_LENGTH  (IO_SUBTYPE_LEN + 1)

#define	NAME_LENGTH (VER_NAME_LEN + OP_NAME_LEN + AXIS_LENGTH)

// Probe functions to initialize thread local data
// @@ kprobe|nfsd_read|nfsd3_read_start
int
nfsd3_read_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *fhp,
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
	return (0);
}

// @@ kprobe|nfsd_write|nfsd3_write_start
int
nfsd3_write_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *fhp,
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
	return (0);
}

// @@ kprobe|nfsd4_read|nfsd4_read_start
int
nfsd4_read_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *cstate,
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
	return (0);
}

// @@ kprobe|nfsd4_write|nfsd4_write_start
int
nfsd4_write_start(struct pt_regs *ctx, struct svc_rqst *rqstp, void *cstate,
    nfsd4_write *nfs_write)
{
	u32 pid = bpf_get_current_pid_tgid();
	nfs_data_t data = {};
	data.ts = bpf_ktime_get_ns();
	data.size = 0;
	data.write_arg = &(nfs_write->wr_bytes_written);
	data.sync = ASYNC_WRITE; // Assume async write, sync writes detected
	data.cached = AXIS_NOT_APPLICABLE;
	bpf_probe_read_str(&data.client, CLIENT_LEN, rqstp->rq_client->name);
	nfs_base_data.update(&pid, &data);

	return (0);
}

// @@ kprobe|trace_zfs_arc__miss|nfs_cache_miss
// @@ kprobe|trace_zfs_blocked__read|nfs_cache_miss
int
nfs_cache_miss(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	nfs_data_t *data = nfs_base_data.lookup(&pid);

	if (data == 0) {
		return (0);   // missed issue
	}

	data->cached = NONCACHED_READ;

	return (0);
}

// @@ kprobe|zil_commit|zil_commit_start
int
zil_commit_start(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	nfs_data_t *data = nfs_base_data.lookup(&pid);

	if (data == 0) {
		return (0);   // missed issue
	}

	data->sync = SYNC_WRITE;
	return (0);
}


// Perform aggregations
static int
aggregate_data(nfs_data_t *data, u64 ts, u32 type, char *verstr)
{
	u64 delta = ts - data->ts;
	char name[NAME_LENGTH] = "";
	char axis[AXIS_LENGTH] = "";

	__builtin_memcpy(&name, verstr, VER_NAME_LEN);
	name[2] = '/';

	if (type == IO_TYPE_WRITE) {
		__builtin_memcpy(&name[3], WRITE_STR, OP_NAME_LEN + 1);
		if (data->sync == 1) {
			__builtin_memcpy(axis, "sync", AXIS_LENGTH);
		} else {
			__builtin_memcpy(axis, "async", AXIS_LENGTH);
		}
	} else if (type == IO_TYPE_READ) {
		__builtin_memcpy(&name[3], READ_STR, OP_NAME_LEN + 1);
		if (data->cached) {
			__builtin_memcpy(axis, "cached", AXIS_LENGTH);
		} else {
			__builtin_memcpy(axis, "uncached", AXIS_LENGTH);
		}
	} else {
		return (0);
	}

	// perform aggregations
	AGGREGATE_DATA(name, axis, delta, data->size);
	return (0);
}

static int
nfsd3_aggregate_data(u64 ts, u32 type)
{
	u32 pid = bpf_get_current_pid_tgid();
	nfs_data_t *data = nfs_base_data.lookup(&pid);

	if (data == 0) {
		return (0);   // missed issue
	}
	bpf_probe_read(&data->size, sizeof (u32), data->write_arg);

	aggregate_data(data, ts, type, NFSV3_STR);
	nfs_base_data.delete(&pid);

	return (0);
}

// Probe functions to aggregate data
// @@ kretprobe|nfsd_read|nfsd3_read_done
int
nfsd3_read_done(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	return (nfsd3_aggregate_data(ts, IO_TYPE_READ));
}

// @@ kretprobe|nfsd_write|nfsd3_write_done
int
nfsd3_write_done(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	return (nfsd3_aggregate_data(ts, IO_TYPE_WRITE));
}

// @@ kretprobe|nfsd4_read_release|nfsd4_read_done
int
nfsd4_read_done(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u32 pid = bpf_get_current_pid_tgid();
	nfs_data_t *data = nfs_base_data.lookup(&pid);

	if (data == 0) {
		return (0);   // missed issue
	}

	aggregate_data(data, ts, IO_TYPE_READ, NFSV4_STR);
	nfs_base_data.delete(&pid);

	return (0);
}

// @@ kretprobe|nfsd4_write|nfsd4_write_done
int
nfsd4_write_done(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u32 pid = bpf_get_current_pid_tgid();
	nfs_data_t *data = nfs_base_data.lookup(&pid);
	u32  wr_bytes_written;

	if (data == 0) {
		return (0);   // missed issue
	}

	bpf_probe_read(&data->size, sizeof (u32), data->write_arg);

	aggregate_data(data, ts, IO_TYPE_WRITE, NFSV4_STR);
	nfs_base_data.delete(&pid);

	return (0);
}
