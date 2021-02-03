/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/uio.h>
#include <sys/condvar.h>
#include <sys/xvattr.h>
#include <sys/zfs_rlock.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_objset.h>
#include <sys/spa_impl.h>

typedef struct {
	u64 start_time;
	u64 bytes;
	bool is_sync;
	bool is_write;
} io_info_t;

// Map of thread id to info about an in-progress IO
BPF_HASH(io_info_map, u32, io_info_t);

#ifndef OPTARG
#define	POOL "domain0"
#else
#define	POOL (OPTARG)
#endif
#define ZFS_READ_SYNC_LENGTH 14
#define ZFS_READ_ASYNC_LENGTH 15
#define ZFS_WRITE_SYNC_LENGTH 15
#define ZFS_WRITE_ASYNC_LENGTH 16

// TODO factor this out into a helper so that it isn't duplicated
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

static inline int
zfs_read_write_entry(io_info_t *info, struct inode *ip, zfs_uio_t *uio, int flags)
{
	// Essentially ITOZSB, but written explicitly so that BCC can insert
	// the necessary calls to bpf_probe_read.
	zfsvfs_t *zfsvfs = ip->i_sb->s_fs_info;

	objset_t *z_os = zfsvfs->z_os;
	spa_t *spa = z_os->os_spa;

	if (!equal_to_pool(spa->spa_name))
		return (0);

	info->start_time = bpf_ktime_get_ns();
	info->bytes = uio->uio_resid;
	info->is_sync =
	    z_os->os_sync == ZFS_SYNC_ALWAYS || (flags & (O_SYNC | O_DSYNC));

	u32 tid = bpf_get_current_pid_tgid();
	io_info_t *infop = io_info_map.lookup(&tid);
	io_info_map.update(&tid, info);

	return (0);
}

// @@ kprobe|zfs_read|zfs_read_entry
int
zfs_read_entry(struct pt_regs *ctx, struct inode *ip, zfs_uio_t *uio, int flags)
{
	io_info_t info = {};
	info.is_write = false;
	return (zfs_read_write_entry(&info, ip, uio, flags));
}

// @@ kprobe|zfs_write|zfs_write_entry
int
zfs_write_entry(struct pt_regs *ctx, struct inode *ip, zfs_uio_t *uio, int flags)
{
	io_info_t info = {};
	info.is_write = true;
	return (zfs_read_write_entry(&info, ip, uio, flags));
}

// @@ kretprobe|zfs_read|zfs_read_write_exit
// @@ kretprobe|zfs_write|zfs_read_write_exit
int
zfs_read_write_exit(struct pt_regs *ctx, struct inode *ip, zfs_uio_t *uio)
{
	u32 tid = bpf_get_current_pid_tgid();
	io_info_t *info = io_info_map.lookup(&tid);
	if (info == NULL) {
		return (0);
	}

	u64 delta = bpf_ktime_get_ns() - info->start_time;

	char name[16];
	int offset;
	if (info->is_write) {
		if (info->is_sync) {
			__builtin_memcpy(name, "zfs_write sync", ZFS_WRITE_SYNC_LENGTH);
		} else {
			__builtin_memcpy(name, "zfs_write async", ZFS_WRITE_ASYNC_LENGTH);
		}
	} else {
		if (info->is_sync) {
			__builtin_memcpy(name, "zfs_read sync", ZFS_READ_SYNC_LENGTH);
		} else {
			__builtin_memcpy(name, "zfs_read async", ZFS_READ_ASYNC_LENGTH);
		}
	}

	char axis = 0;
	AGGREGATE_DATA(name, &axis, delta, info->bytes);
	io_info_map.delete(&tid);

	return (0);
}
