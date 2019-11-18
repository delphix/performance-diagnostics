/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>
#include <sys/zio.h>
#include <sys/spa_impl.h>

// Structure to hold thread local data
typedef struct {
	u64 ts;
} zio_data_t;

BPF_HASH(zio_base_data, zio_t *, zio_data_t);

#define	OP_LENGTH 6
#define	PRIORITY_LENGTH 7

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

// @@ kprobe|vdev_queue_io_add|vdev_queue_add
int
vdev_queue_add(struct pt_regs *ctx, void *vq, zio_t *zio)
{
	zio_data_t data = {};
	data.ts = bpf_ktime_get_ns();

	if (zio == NULL)
		return (0);

	if (! equal_to_pool(zio->io_spa->spa_name))
		return (0);

	zio_base_data.update(&zio, &data);

	return (0);
}

// @@ kprobe|vdev_queue_io_remove|vdev_queue_remove
int
vdev_queue_remove(struct pt_regs *ctx, void *vq, zio_t *zio)
{
	u64 ts = bpf_ktime_get_ns();
	zio_data_t *data = zio_base_data.lookup(&zio);
	if (data == 0) {
		return (0);   // missed issue
	}


	u64 delta = ts - data->ts;
	char name[OP_LENGTH];
	char axis[PRIORITY_LENGTH];

	if (zio->io_type == 1) {
		__builtin_memcpy(&name, "read", OP_LENGTH);
	} else if (zio->io_type == 2) {
		__builtin_memcpy(&name, "write", OP_LENGTH);
	} else if (zio->io_type == 3) {
		__builtin_memcpy(&name, "free", OP_LENGTH);
	} else if (zio->io_type == 4) {
		__builtin_memcpy(&name, "claim", OP_LENGTH);
	} else if (zio->io_type == 5) {
		__builtin_memcpy(&name, "ioctl", OP_LENGTH);
	} else {
		__builtin_memcpy(&name, "null", OP_LENGTH);
	}

	if (zio->io_priority == 0) {
		__builtin_memcpy(&axis, "syncr", PRIORITY_LENGTH);
	} else if (zio->io_priority == 1) {
		__builtin_memcpy(&axis, "syncw", PRIORITY_LENGTH);
	} else if (zio->io_priority == 2) {
		__builtin_memcpy(&axis, "asyncr", PRIORITY_LENGTH);
	} else if (zio->io_priority == 3) {
		__builtin_memcpy(&axis, "asyncw", PRIORITY_LENGTH);
	} else if (zio->io_priority == 4) {
		__builtin_memcpy(&axis, "scrub", PRIORITY_LENGTH);
	}

	AGGREGATE_DATA(name, axis, delta, zio->io_size);
	zio_base_data.delete(&zio);

	return (0);
}
