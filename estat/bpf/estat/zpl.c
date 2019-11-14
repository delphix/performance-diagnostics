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
#define POOL "domain0"
#else
#define POOL (OPTARG)
#endif

// TODO factor this out into a helper so that it isn't duplicated
static inline bool equal_to_pool(char *str) {
    char comparand[sizeof(POOL)];
    bpf_probe_read(&comparand, sizeof(comparand), str);
    char compare[] = POOL;
    for (int i = 0; i < sizeof(comparand); ++i)
        if (compare[i] != comparand[i])
            return false;
    return true;
}

static inline int zfs_read_write_entry(io_info_t *info, struct inode *ip, uio_t *uio, int flags) {
	// Essentially ITOZSB, but written explicitly so that BCC can insert
	// the necessary calls to bpf_probe_read.
	zfsvfs_t *zfsvfs = ip->i_sb->s_fs_info;

	objset_t *z_os = zfsvfs->z_os;
	spa_t *spa = z_os->os_spa;

	if (!equal_to_pool(spa->spa_name))
		return 0;

	info->start_time = bpf_ktime_get_ns();
	info->bytes = uio->uio_resid;
	info->is_sync = z_os->os_sync == ZFS_SYNC_ALWAYS || (flags & (FSYNC | FDSYNC));

	u32 tid = bpf_get_current_pid_tgid();
	io_info_t *infop = io_info_map.lookup(&tid);
	io_info_map.update(&tid, info);

	return 0;
}

// @@ kprobe|zfs_read|zfs_read_entry
int zfs_read_entry(struct pt_regs *ctx, struct inode *ip, uio_t *uio, int flags) {
	io_info_t info = {};
	info.is_write = false;
	return zfs_read_write_entry(&info, ip, uio, flags);
}

// @@ kprobe|zfs_write|zfs_write_entry
int zfs_write_entry(struct pt_regs *ctx, struct inode *ip, uio_t *uio, int flags) {
	io_info_t info = {};
	info.is_write = true;
	return zfs_read_write_entry(&info, ip, uio, flags);
}

// @@ kretprobe|zfs_read|zfs_read_write_exit
// @@ kretprobe|zfs_write|zfs_read_write_exit
int zfs_read_write_exit(struct pt_regs *ctx, struct inode *ip, uio_t *uio) {
	u32 tid = bpf_get_current_pid_tgid();
	io_info_t *info = io_info_map.lookup(&tid);
	if (info == NULL) {
		return 0;
	}

	u64 delta = bpf_ktime_get_ns() - info->start_time;

	char name[32];
	int offset;
	if (info->is_write) {
		const char s[] = "zfs_write";
		__builtin_memcpy(&name, s, sizeof(s));
		offset = sizeof(s) - 1;
	} else {
		const char s[] = "zfs_read";
		__builtin_memcpy(&name, s, sizeof(s));
		offset = sizeof(s) - 1;
	}

	if (info->is_sync) {
		const char s[] = " sync";
		__builtin_memcpy(name + offset, s, sizeof(s));
	} else {
		const char s[] = " async";
		__builtin_memcpy(name + offset, s, sizeof(s));
	}

	char axis = 0;
	AGGREGATE_DATA(name, &axis, delta, info->bytes);
	io_info_map.delete(&tid);

	return 0;
}
