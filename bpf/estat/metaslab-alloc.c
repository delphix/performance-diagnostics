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
	u64 size;
	u64 asize;
	u64 alloc_time;
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
	data->alloc_time = bpf_ktime_get_ns();

	if (mg->mg_vd->vdev_path != NULL) {
		bpf_probe_read_str(data->vd_name,
		    sizeof(data->vd_name), mg->mg_vd->vdev_path);
	} else {
		bpf_probe_read_str(data->vd_name,
		    sizeof(data->vd_name), mg->mg_vd->vdev_ops->vdev_op_type);
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

	if (PT_REGS_RC(ctx) == -1ULL) {
		axis = failure;
	} else {
		axis = success;
	}

	AGGREGATE_DATA(data->vd_name, axis,
		bpf_ktime_get_ns() - data->ts, data->asize);

	data->asize = 0;
	data->alloc_time = 0;
	data->vd_name[0] = '\0';

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

	if (PT_REGS_RC(ctx) == 0)
		return (0);

	char name[] = "allocation failures";
	char axis = 0;
	AGGREGATE_DATA(name, &axis,
		bpf_ktime_get_ns() - data->ts, data->size);

	data->ts = 0;
	data->size = 0;

	data_map.delete(&tid);

	return (0);
}
