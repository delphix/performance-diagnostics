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
 * In ZFS 2.4.99+ (2026.3 and later) the allocation path no longer goes
 * through metaslab_alloc_dva at all — metaslab_group_alloc is called
 * directly by a different caller.  We therefore use metaslab_group_alloc
 * as both the start-timing and pool-filter point.  The pool name is
 * available via mg->mg_class->mc_spa->spa_name.
 *
 * On older ZFS versions metaslab_alloc_dva is still the outer entry point.
 * We probe it only to set up the data_map entry that metaslab_group_alloc
 * then populates with vdev information.  If metaslab_alloc_dva is not
 * kprobeable (BPF.get_kprobe_functions returns false), estat.py prints a
 * warning and skips the attach — metaslab_group_alloc_entry handles that
 * case via the mc_spa pool check instead.
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

	data.ts = bpf_ktime_get_ns();

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

	if (data != NULL && data->ts != 0) {
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
		metaslab_class_t *mc;
		spa_t *spa;
		bpf_probe_read(&mc, sizeof(mc), &mg->mg_class);
		bpf_probe_read(&spa, sizeof(spa), &mc->mc_spa);
		if (!equal_to_pool(spa->spa_name))
			return (0);

		data_t d = {};
		d.ts    = bpf_ktime_get_ns();
		d.asize = asize;

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
	 * The old code checked for -1ULL which was never a valid failure
	 * value; corrected here based on observed probe data (all successful
	 * allocations return non-zero).
	 */
	if (PT_REGS_RC(ctx) == 0) {
		axis = failure;
	} else {
		axis = success;
	}

	/*
	 * Guard against garbage in vd_name (DLPX-88427): a kernel bug on
	 * some engine versions causes raw memory bytes to appear here.
	 * Valid vdev names start with '/' or an ASCII letter (0x20-0x7e).
	 */
	if (data->vd_name[0] < 0x20 || data->vd_name[0] > 0x7e) {
		char unknown[] = "unknown";
		__builtin_memcpy(data->vd_name, unknown, sizeof(unknown));
	}

	AGGREGATE_DATA(data->vd_name, axis,
		bpf_ktime_get_ns() - data->ts, data->asize);

	data_map.delete(&tid);

	return (0);
}

// @@ kretprobe|metaslab_alloc_dva|metaslab_alloc_dva_exit
int
metaslab_alloc_dva_exit(struct pt_regs *ctx,
    spa_t *spa, metaslab_class_t *mc, uint64_t psize)
{
	u32 tid = bpf_get_current_pid_tgid();
	data_t *data = data_map.lookup(&tid);

	if (data == NULL || data->ts == 0)
		return (0);

	/*
	 * On the older code path, metaslab_alloc_dva_entry created the map
	 * entry but metaslab_group_alloc_exit will have already deleted it
	 * on success.  If we arrive here with a live entry it means the
	 * overall DVA allocation failed; clean up the map.
	 */
	data->ts = 0;
	data_map.delete(&tid);

	return (0);
}
