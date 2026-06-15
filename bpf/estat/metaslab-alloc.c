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
	u64 size;      /* psize stored by metaslab_alloc_dva_entry (old path) */
	u64 asize;
	u8  dva_owned; /* 1 if created by metaslab_alloc_dva_entry (old path) */
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
 * In ZFS 2.4.99+ (2026.3 and later) the allocation path no longer goes
 * through metaslab_alloc_dva at all — metaslab_group_alloc is called
 * directly by a different caller.  We therefore use metaslab_group_alloc
 * as both the start-timing and pool-filter point.  The pool name is
 * available via mg->mg_class->mc_spa->spa_name.
 *
 * On older ZFS versions metaslab_alloc_dva is still the outer entry point.
 * We probe it to set up the data_map entry (dva_owned=1) and store psize so
 * metaslab_alloc_dva_exit can emit an "allocation failures" metric if the
 * overall DVA allocation fails.  metaslab_group_alloc_entry then populates
 * vdev information into the same entry.
 *
 * Lifetime of map entries:
 *   Old path: created by metaslab_alloc_dva_entry, deleted by
 *             metaslab_alloc_dva_exit (metaslab_group_alloc_exit only
 *             clears per-group fields so multiple groups can be tried).
 *   New path: created and deleted by metaslab_group_alloc_entry/exit pair
 *             (no outer dva probe fires).
 */

// @@ kprobe|metaslab_alloc_dva|metaslab_alloc_dva_entry
int
metaslab_alloc_dva_entry(struct pt_regs *ctx,
    spa_t *spa, metaslab_class_t *mc, uint64_t psize)
{
	u32 tid = bpf_get_current_pid_tgid();
	data_t data = {};

	if (!equal_to_pool(spa->spa_name))
		return (0);

	data.ts        = bpf_ktime_get_ns();
	data.size      = psize;
	data.dva_owned = 1;

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

	if (data != NULL && data->dva_owned) {
		/*
		 * Older path: metaslab_alloc_dva_entry already created the
		 * entry and set the start timestamp.  Just fill in vdev info.
		 */
		data->asize = asize;
		if (mg->mg_vd->vdev_path != NULL) {
			bpf_probe_read_str(data->vd_name,
			    sizeof(data->vd_name), mg->mg_vd->vdev_path);
		} else {
			bpf_probe_read_str(data->vd_name,
			    sizeof(data->vd_name),
			    mg->mg_vd->vdev_ops->vdev_op_type);
		}
	} else {
		/*
		 * Newer path: metaslab_alloc_dva is not in the call chain.
		 * Create the entry here, filtering by pool via mc_spa.
		 * Read each pointer level explicitly: BCC's automatic
		 * three-level dereference (mg->mg_class->mc_spa->spa_name)
		 * does not produce a usable address for bpf_probe_read.
		 */
		metaslab_class_t *mc = NULL;
		spa_t *spa = NULL;
		bpf_probe_read(&mc, sizeof(mc), &mg->mg_class);
		if (!mc)
			return (0);
		bpf_probe_read(&spa, sizeof(spa), &mc->mc_spa);
		if (!spa)
			return (0);
		if (!equal_to_pool(spa->spa_name))
			return (0);

		data_t d = {};
		d.ts    = bpf_ktime_get_ns();
		d.asize = asize;
		/* dva_owned stays 0: this entry is owned by group entry/exit */

		if (mg->mg_vd->vdev_path != NULL) {
			bpf_probe_read_str(d.vd_name,
			    sizeof(d.vd_name), mg->mg_vd->vdev_path);
		} else {
			bpf_probe_read_str(d.vd_name,
			    sizeof(d.vd_name),
			    mg->mg_vd->vdev_ops->vdev_op_type);
		}

		data_map.update(&tid, &d);
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

	/*
	 * metaslab_group_alloc returns a metaslab_t * (or similar pointer)
	 * in both old and new ZFS.  NULL (0) = failure, non-NULL = success.
	 */
	if (PT_REGS_RC(ctx) == 0) {
		axis = failure;
	} else {
		axis = success;
	}

	/*
	 * Guard against garbage in vd_name (DLPX-88427): a kernel bug on
	 * some engine versions causes raw memory bytes to appear here.
	 * A single non-printable byte anywhere in the string breaks JSON
	 * output (Python decodes with backslashreplace and the result is
	 * concatenated into JSON without escaping).  Scan all bytes up to
	 * the first NUL; replace the whole name with "unknown" if the
	 * string is empty or any byte is outside printable ASCII (0x20-0x7e).
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

	if (data->dva_owned) {
		/*
		 * Old path: metaslab_alloc_dva may call metaslab_group_alloc
		 * multiple times (one per group tried).  Reset per-group fields
		 * so the next attempt gets a fresh vdev name, but leave the
		 * entry alive so metaslab_alloc_dva_exit can record an
		 * "allocation failures" metric if the overall DVA fails.
		 */
		data->asize      = 0;
		data->vd_name[0] = '\0';
	} else {
		/* New path: no outer dva exit will run; clean up now. */
		data_map.delete(&tid);
	}

	return (0);
}

// @@ kretprobe|metaslab_alloc_dva|metaslab_alloc_dva_exit
int
metaslab_alloc_dva_exit(struct pt_regs *ctx,
    spa_t *spa, metaslab_class_t *mc, uint64_t psize)
{
	/* spa, mc, psize match the probed function signature but are unused. */
	(void)spa; (void)mc; (void)psize;

	u32 tid = bpf_get_current_pid_tgid();
	data_t *data = data_map.lookup(&tid);

	if (data == NULL || data->ts == 0)
		return (0);

	/*
	 * A live entry exists on both success and failure paths; only the
	 * return code determines whether to emit an "allocation failures"
	 * metric (non-zero RC = failure).  psize is read from data->size
	 * rather than the kretprobe argument registers, which may be
	 * clobbered by the time the function returns.
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
