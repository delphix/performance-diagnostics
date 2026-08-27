/*
 * Copyright 2020 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/metaslab.h>
#include <sys/metaslab_impl.h>
#include <sys/vdev_impl.h>
#include <sys/spa_impl.h>

#define VD_NAME_SIZE 32
typedef struct {
	u64 ts;
	u64 size;	/* psize from metaslab_alloc_dva_range_entry */
	u64 asize;
	char vd_name[VD_NAME_SIZE];
} data_t;

BPF_HASH(data_map, u32, data_t);

#ifndef OPTARG
#define	POOL "domain0"
#else
#define	POOL (OPTARG)
#endif

static inline bool
equal_to_pool(char *str)
{
	char comparand[sizeof (POOL)];
	bpf_probe_read(&comparand, sizeof (comparand), str);
	char compare[] = POOL;

	for (int i = 0; i < sizeof (comparand); ++i)
		if (compare[i] != comparand[i])
			return (false);

	return (true);
}

/*
 * metaslab_alloc_dva_range() is the per-DVA entry point in the write path
 * for ZFS versions that have it (Delphix 2026.3 / ZFS 2.4.99+).  It receives
 * spa_t * as its first argument, making pool filtering straightforward.
 *
 * Call chain:
 *   metaslab_alloc()
 *     -> metaslab_alloc_range()
 *       -> metaslab_alloc_dva_range()   <- outer probe (entry/exit)
 *           -> metaslab_group_alloc()   <- inner probe (entry/exit)
 *
 * metaslab_alloc_dva_range() may call metaslab_group_alloc() multiple times
 * (once per metaslab group tried).  We therefore emit a metric on each
 * metaslab_group_alloc_exit and reset the per-group fields so the next
 * attempt gets a fresh vdev name, leaving the outer entry alive until
 * metaslab_alloc_dva_range_exit cleans it up.
 *
 * metaslab_alloc_dva() (the old outer entry point, now only used in
 * vdev_removal.c) is no longer probed.  If this script is run on an older
 * ZFS that lacks metaslab_alloc_dva_range, estat(8) will print a WARNING and
 * skip those probes — no data will be collected.
 */

// @@ kprobe|metaslab_alloc_dva_range|metaslab_alloc_dva_range_entry
int
metaslab_alloc_dva_range_entry(struct pt_regs *ctx,
    spa_t *spa, metaslab_class_t *mc, uint64_t psize)
{
	u32 tid = bpf_get_current_pid_tgid();
	data_t data = {};

	if (!equal_to_pool(spa->spa_name))
		return (0);

	data.ts   = bpf_ktime_get_ns();
	data.size = psize;

	data_map.update(&tid, &data);

	return (0);
}

// @@ kprobe|metaslab_group_alloc|metaslab_group_alloc_entry
int
metaslab_group_alloc_entry(struct pt_regs *ctx,
    metaslab_group_t *mg, zio_alloc_list_t *zal, uint64_t asize)
{
	u32 tid = bpf_get_current_pid_tgid();
	data_t *data = data_map.lookup(&tid);

	if (data == NULL || data->ts == 0)
		return (0);

	data->asize = asize;

	if (mg->mg_vd->vdev_path != NULL) {
		bpf_probe_read_str(data->vd_name,
		    sizeof(data->vd_name), mg->mg_vd->vdev_path);
	} else {
		bpf_probe_read_str(data->vd_name,
		    sizeof(data->vd_name),
		    mg->mg_vd->vdev_ops->vdev_op_type);
	}

	return (0);
}

// @@ kretprobe|metaslab_group_alloc|metaslab_group_alloc_exit
int
metaslab_group_alloc_exit(struct pt_regs *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	data_t *data = data_map.lookup(&tid);
	char failure[] = "failure";
	char success[] = "success";
	char *axis;

	if (data == NULL || data->ts == 0)
		return (0);

	if (PT_REGS_RC(ctx) == 0) {
		axis = failure;
	} else {
		axis = success;
	}

	/*
	 * Guard against garbage in vd_name (DLPX-88427): a kernel bug on
	 * some engine versions causes raw memory bytes to appear here.
	 * A single non-printable byte anywhere in the string breaks JSON
	 * output.  Scan all bytes up to the first NUL; replace the whole
	 * name with "unknown" if empty or any byte is outside printable
	 * ASCII (0x20-0x7e).
	 */
	bool vd_valid = (data->vd_name[0] != '\0');
#pragma unroll
	for (int _i = 0; _i < VD_NAME_SIZE; _i++) {
		char _c = data->vd_name[_i];
		if (_c == '\0')
			break;
		if (_c < 0x20 || _c > 0x7e)
			vd_valid = false;
	}
	if (!vd_valid) {
		char unknown[] = "unknown";
		__builtin_memcpy(data->vd_name, unknown, sizeof(unknown));
	}

	AGGREGATE_DATA(data->vd_name, axis,
		bpf_ktime_get_ns() - data->ts, data->asize);

	/*
	 * Reset per-group fields so that if metaslab_alloc_dva_range retries
	 * with another group, metaslab_group_alloc_entry gets a clean slate.
	 * Leave the entry alive — metaslab_alloc_dva_range_exit owns cleanup.
	 */
	data->asize      = 0;
	data->vd_name[0] = '\0';

	return (0);
}

// @@ kretprobe|metaslab_alloc_dva_range|metaslab_alloc_dva_range_exit
int
metaslab_alloc_dva_range_exit(struct pt_regs *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	data_t *data = data_map.lookup(&tid);

	if (data == NULL || data->ts == 0)
		return (0);

	/*
	 * Non-zero return means the overall DVA allocation failed (no group
	 * succeeded).  Emit an "allocation failures" metric using the psize
	 * stored at entry time; the kretprobe argument registers may be
	 * clobbered so we read from data->size instead.
	 */
	if (PT_REGS_RC(ctx) != 0) {
		char name[] = "allocation failures";
		char axis = 0;
		AGGREGATE_DATA(name, &axis,
			bpf_ktime_get_ns() - data->ts, data->size);
	}

	data->ts = 0;
	data_map.delete(&tid);

	return (0);
}
